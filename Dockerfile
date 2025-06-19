# Use Python 3.13 as a parent image
FROM python:3.13-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the src directory into the container
COPY ./src .

# Make port 80 available to the world outside this container
EXPOSE 80

# Define environment variables
ENV NAME CNAGradeCard

# Run api.py when the container launches
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "80"]
