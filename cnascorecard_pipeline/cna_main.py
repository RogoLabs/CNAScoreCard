#!/usr/bin/env python3
"""
CNA Growth Forecasting Script
Analyzes CVE publication patterns by CNA and generates 12-month forecasts
using LightGBM, XGBoost, and Prophet models.
"""

import json
import os
import sys
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path
import logging

import pandas as pd
import numpy as np
from dateutil import parser
import warnings
warnings.filterwarnings('ignore')

# Machine Learning Models
try:
    import lightgbm as lgb
    import xgboost as xgb
    from prophet import Prophet
    from sklearn.metrics import mean_absolute_percentage_error
    from sklearn.preprocessing import StandardScaler
except ImportError as e:
    print(f"Error importing required libraries: {e}")
    print("Please install: pip install lightgbm xgboost prophet scikit-learn pandas numpy")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CNAForecastingEngine:
    """Main class for CNA growth forecasting"""
    
    def __init__(self):
        self.cve_data_path = "cve_data"
        self.output_path = "web/cna_data.json"
        self.min_cve_threshold = 100  # Minimum CVEs for meaningful forecasting
        
        # Model configurations (optimized hyperparameters)
        self.model_configs = {
            'lightgbm': {
                'objective': 'regression',
                'metric': 'mape',
                'boosting_type': 'gbdt',
                'num_leaves': 31,
                'learning_rate': 0.05,
                'feature_fraction': 0.9,
                'bagging_fraction': 0.8,
                'bagging_freq': 5,
                'verbose': -1,
                'random_state': 42
            },
            'xgboost': {
                'objective': 'reg:squarederror',
                'eval_metric': 'mape',
                'max_depth': 6,
                'learning_rate': 0.1,
                'n_estimators': 100,
                'subsample': 0.8,
                'colsample_bytree': 0.8,
                'random_state': 42
            },
            'prophet': {
                'changepoint_prior_scale': 0.05,
                'seasonality_prior_scale': 10.0,
                'holidays_prior_scale': 10.0,
                'seasonality_mode': 'multiplicative',
                'yearly_seasonality': True,
                'weekly_seasonality': False,
                'daily_seasonality': False
            }
        }
    
    def load_cve_data(self):
        """Load and parse CVE data from the cvelistV5 repository"""
        logger.info("Loading CVE data from repository...")
        
        cve_records = []
        cve_path = Path(self.cve_data_path) / "cves"
        
        if not cve_path.exists():
            logger.error(f"CVE data path not found: {cve_path}")
            return []
        
        # Process CVE files by year (focus on recent years for performance)
        years_to_process = range(2018, datetime.now().year + 1)
        
        for year in years_to_process:
            year_path = cve_path / str(year)
            if not year_path.exists():
                continue
                
            logger.info(f"Processing CVEs from {year}...")
            
            for cve_file in year_path.rglob("CVE-*.json"):
                try:
                    with open(cve_file, 'r', encoding='utf-8') as f:
                        cve_data = json.load(f)
                    
                    # Extract relevant information
                    cve_id = cve_data.get('cveMetadata', {}).get('cveId', '')
                    date_published = cve_data.get('cveMetadata', {}).get('datePublished', '')
                    
                    # Extract CNA information
                    containers = cve_data.get('containers', {})
                    cna_info = containers.get('cna', {})
                    provider_metadata = cna_info.get('providerMetadata', {})
                    cna_id = provider_metadata.get('shortName', '')
                    
                    if cve_id and date_published and cna_id:
                        try:
                            pub_date = parser.parse(date_published).date()
                            cve_records.append({
                                'cve_id': cve_id,
                                'cna_id': cna_id,
                                'date_published': pub_date,
                                'year_month': f"{pub_date.year}-{pub_date.month:02d}"
                            })
                        except Exception as e:
                            logger.debug(f"Date parsing error for {cve_id}: {e}")
                            continue
                
                except Exception as e:
                    logger.debug(f"Error processing {cve_file}: {e}")
                    continue
        
        logger.info(f"Loaded {len(cve_records)} CVE records")
        return cve_records
    
    def prepare_time_series_data(self, cve_records):
        """Prepare monthly time series data for each CNA"""
        logger.info("Preparing time series data...")
        
        # Group by CNA and month
        cna_monthly_counts = defaultdict(lambda: defaultdict(int))
        
        for record in cve_records:
            cna_id = record['cna_id']
            year_month = record['year_month']
            cna_monthly_counts[cna_id][year_month] += 1
        
        # Filter CNAs with sufficient data
        qualified_cnas = {}
        for cna_id, monthly_data in cna_monthly_counts.items():
            total_cves = sum(monthly_data.values())
            if total_cves >= self.min_cve_threshold:
                qualified_cnas[cna_id] = monthly_data
        
        logger.info(f"Found {len(qualified_cnas)} CNAs with >{self.min_cve_threshold} CVEs")
        
        # Convert to time series format
        cna_time_series = {}
        
        for cna_id, monthly_data in qualified_cnas.items():
            # Create complete date range
            all_months = sorted(monthly_data.keys())
            if not all_months:
                continue
                
            start_date = datetime.strptime(all_months[0], "%Y-%m").date()
            end_date = datetime.strptime(all_months[-1], "%Y-%m").date()
            
            # Generate complete monthly series
            current_date = start_date.replace(day=1)
            time_series = []
            
            while current_date <= end_date:
                year_month = f"{current_date.year}-{current_date.month:02d}"
                count = monthly_data.get(year_month, 0)
                time_series.append({
                    'date': current_date,
                    'year_month': year_month,
                    'count': count
                })
                
                # Move to next month
                if current_date.month == 12:
                    current_date = current_date.replace(year=current_date.year + 1, month=1)
                else:
                    current_date = current_date.replace(month=current_date.month + 1)
            
            cna_time_series[cna_id] = time_series
        
        return cna_time_series
    
    def create_features(self, time_series):
        """Create features for machine learning models"""
        df = pd.DataFrame(time_series)
        df['date'] = pd.to_datetime(df['date'])
        df = df.sort_values('date').reset_index(drop=True)
        
        # Time-based features
        df['month'] = df['date'].dt.month
        df['quarter'] = df['date'].dt.quarter
        df['year'] = df['date'].dt.year
        df['days_since_start'] = (df['date'] - df['date'].min()).dt.days
        
        # Lag features
        for lag in [1, 2, 3, 6, 12]:
            df[f'lag_{lag}'] = df['count'].shift(lag)
        
        # Rolling statistics
        for window in [3, 6, 12]:
            df[f'rolling_mean_{window}'] = df['count'].rolling(window=window, min_periods=1).mean()
            df[f'rolling_std_{window}'] = df['count'].rolling(window=window, min_periods=1).std()
        
        # Trend features
        df['trend'] = range(len(df))
        
        return df
    
    def train_lightgbm(self, df):
        """Train LightGBM model"""
        feature_cols = [col for col in df.columns if col not in ['date', 'year_month', 'count']]
        
        # Prepare training data (use last 80% for training)
        train_size = int(len(df) * 0.8)
        train_df = df[:train_size].copy()
        
        # Handle missing values
        train_df = train_df.fillna(0)
        
        X_train = train_df[feature_cols]
        y_train = train_df['count']
        
        # Train model
        train_data = lgb.Dataset(X_train, label=y_train)
        model = lgb.train(
            self.model_configs['lightgbm'],
            train_data,
            num_boost_round=100,
            valid_sets=[train_data],
            callbacks=[lgb.early_stopping(10), lgb.log_evaluation(0)]
        )
        
        return model, feature_cols
    
    def train_xgboost(self, df):
        """Train XGBoost model"""
        feature_cols = [col for col in df.columns if col not in ['date', 'year_month', 'count']]
        
        # Prepare training data
        train_size = int(len(df) * 0.8)
        train_df = df[:train_size].copy()
        
        # Handle missing values
        train_df = train_df.fillna(0)
        
        X_train = train_df[feature_cols]
        y_train = train_df['count']
        
        # Train model
        model = xgb.XGBRegressor(**self.model_configs['xgboost'])
        model.fit(X_train, y_train)
        
        return model, feature_cols
    
    def train_prophet(self, df):
        """Train Prophet model"""
        # Prepare data for Prophet
        prophet_df = df[['date', 'count']].copy()
        prophet_df.columns = ['ds', 'y']
        
        # Train model
        model = Prophet(**self.model_configs['prophet'])
        model.fit(prophet_df)
        
        return model
    
    def generate_forecasts(self, cna_id, time_series):
        """Generate forecasts for a single CNA using all models"""
        logger.info(f"Generating forecasts for {cna_id}...")
        
        if len(time_series) < 12:  # Need at least 12 months of data
            logger.warning(f"Insufficient data for {cna_id}: {len(time_series)} months")
            return None
        
        # Prepare data
        df = self.create_features(time_series)
        
        forecasts = {}
        
        try:
            # LightGBM forecast
            lgb_model, feature_cols = self.train_lightgbm(df)
            
            # Generate future dates
            last_date = df['date'].max()
            future_dates = []
            for i in range(1, 13):  # 12 months ahead
                future_date = last_date + pd.DateOffset(months=i)
                future_dates.append(future_date)
            
            # Create future features
            future_df = pd.DataFrame({'date': future_dates})
            future_df['month'] = future_df['date'].dt.month
            future_df['quarter'] = future_df['date'].dt.quarter
            future_df['year'] = future_df['date'].dt.year
            future_df['days_since_start'] = (future_df['date'] - df['date'].min()).dt.days
            future_df['trend'] = range(len(df), len(df) + 12)
            
            # Add lag features (use recent values)
            for lag in [1, 2, 3, 6, 12]:
                if lag <= len(df):
                    future_df[f'lag_{lag}'] = df['count'].iloc[-lag]
                else:
                    future_df[f'lag_{lag}'] = df['count'].mean()
            
            # Add rolling features
            for window in [3, 6, 12]:
                recent_mean = df['count'].tail(window).mean()
                recent_std = df['count'].tail(window).std()
                future_df[f'rolling_mean_{window}'] = recent_mean
                future_df[f'rolling_std_{window}'] = recent_std if not pd.isna(recent_std) else 0
            
            future_df = future_df.fillna(0)
            lgb_pred = lgb_model.predict(future_df[feature_cols])
            lgb_pred = np.maximum(lgb_pred, 0)  # Ensure non-negative
            forecasts['lightgbm'] = lgb_pred.tolist()
            
        except Exception as e:
            logger.error(f"LightGBM error for {cna_id}: {e}")
            forecasts['lightgbm'] = [0] * 12
        
        try:
            # XGBoost forecast
            xgb_model, feature_cols = self.train_xgboost(df)
            xgb_pred = xgb_model.predict(future_df[feature_cols])
            xgb_pred = np.maximum(xgb_pred, 0)
            forecasts['xgboost'] = xgb_pred.tolist()
            
        except Exception as e:
            logger.error(f"XGBoost error for {cna_id}: {e}")
            forecasts['xgboost'] = [0] * 12
        
        try:
            # Prophet forecast
            prophet_model = self.train_prophet(df)
            future_prophet = prophet_model.make_future_dataframe(periods=12, freq='M')
            prophet_pred = prophet_model.predict(future_prophet)
            prophet_forecast = prophet_pred['yhat'].tail(12).values
            prophet_forecast = np.maximum(prophet_forecast, 0)
            forecasts['prophet'] = prophet_forecast.tolist()
            
        except Exception as e:
            logger.error(f"Prophet error for {cna_id}: {e}")
            forecasts['prophet'] = [0] * 12
        
        # Calculate historical statistics
        historical_counts = [record['count'] for record in time_series]
        total_historical = sum(historical_counts)
        
        # Calculate average forecast
        avg_forecast = []
        for i in range(12):
            month_predictions = []
            for model in ['lightgbm', 'xgboost', 'prophet']:
                if model in forecasts:
                    month_predictions.append(forecasts[model][i])
            avg_forecast.append(sum(month_predictions) / len(month_predictions) if month_predictions else 0)
        
        return {
            'cna_id': cna_id,
            'total_historical_cves': total_historical,
            'historical_monthly_counts': historical_counts,
            'historical_dates': [record['year_month'] for record in time_series],
            'forecasts': forecasts,
            'average_forecast': avg_forecast,
            'forecast_total_12_months': sum(avg_forecast)
        }
    
    def run_forecasting(self):
        """Main forecasting pipeline"""
        logger.info("Starting CNA forecasting pipeline...")
        
        # Load CVE data
        cve_records = self.load_cve_data()
        if not cve_records:
            logger.error("No CVE data loaded. Exiting.")
            return
        
        # Prepare time series data
        cna_time_series = self.prepare_time_series_data(cve_records)
        
        # Generate forecasts for each CNA
        all_forecasts = {}
        
        for cna_id, time_series in cna_time_series.items():
            try:
                forecast_result = self.generate_forecasts(cna_id, time_series)
                if forecast_result:
                    all_forecasts[cna_id] = forecast_result
            except Exception as e:
                logger.error(f"Error forecasting for {cna_id}: {e}")
                continue
        
        # Save results
        os.makedirs(os.path.dirname(self.output_path), exist_ok=True)
        
        output_data = {
            'generated_at': datetime.now().isoformat(),
            'total_cnas_forecasted': len(all_forecasts),
            'forecast_horizon_months': 12,
            'models_used': ['lightgbm', 'xgboost', 'prophet'],
            'cna_forecasts': all_forecasts
        }
        
        with open(self.output_path, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, default=str)
        
        logger.info(f"Forecasting complete. Results saved to {self.output_path}")
        logger.info(f"Generated forecasts for {len(all_forecasts)} CNAs")

def main():
    """Main entry point"""
    try:
        engine = CNAForecastingEngine()
        engine.run_forecasting()
    except Exception as e:
        logger.error(f"Pipeline failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
