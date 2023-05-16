# Use the official Python base image
FROM python:3.10.11

# Set the working directory in the container
WORKDIR /app

# Copy the project files into the container
COPY . /app

# Install project dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose any necessary ports (if applicable)
# EXPOSE <port>

# Define the command to run the application
CMD ["python", "src/main.py"]

