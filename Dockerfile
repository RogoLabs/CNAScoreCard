# Use Python 3.13 as a parent image
FROM python:3.13

# Install git
RUN apt-get update && apt-get install -y git

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the main application directory into the container
COPY ./cnagradecard ./cnagradecard

# Make port 80 available to the world outside this container
EXPOSE 80

# Define environment variables
ENV NAME="CNAGradeCard"

# Run the uvicorn server, pointing to the 'app' instance in 'api.py' within the 'cnagradecard' module
CMD ["uvicorn", "cnagradecard.api:app", "--host", "0.0.0.0", "--port", "80"]