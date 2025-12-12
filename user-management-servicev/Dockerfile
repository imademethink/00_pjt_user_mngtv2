# Use a Python base image
FROM python:3.10-slim

# Set environment variable for unbuffered output
ENV PYTHONUNBUFFERED 1

# Set the working directory in the container
WORKDIR /usr/src/app/user_mngt

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . .

# Expose the port the app runs on
EXPOSE 5000

# Command to run the application
CMD ["python", "user_mngt_app.py"]
