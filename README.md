# ZM-BACK-END

This is the backend service for the ZM application.

## Docker Setup

This project includes a Dockerfile to containerize the application. Follow these instructions to build and run the Docker image.

### Prerequisites

- Docker installed on your machine
- Java 23 (for local development)
- Maven (for local development)

### Building the Docker Image

To build the Docker image, run the following command from the project root directory:

```bash
docker build -t zm-backend .
```

### Running the Docker Container

To run the Docker container, use the following command:

```bash
docker run -p 8080:8080 zm-backend
```

This will start the application and expose it on port 8080.

### Environment Variables

The following environment variables can be configured when running the container:

- `PORT`: The port the application runs on (default: 8080)
- `SPRING_DATASOURCE_URL`: JDBC URL for the MySQL database
- `SPRING_DATASOURCE_USERNAME`: Database username
- `SPRING_DATASOURCE_PASSWORD`: Database password
- `GOOGLE_CLIENT_ID`: Google OAuth2 client ID
- `GOOGLE_CLIENT_SECRET`: Google OAuth2 client secret
- `FACEBOOK_CLIENT_ID`: Facebook OAuth2 client ID
- `FACEBOOK_CLIENT_SECRET`: Facebook OAuth2 client secret
- `EMAIL_USERNAME`: Email username for SMTP
- `EMAIL_PASSWORD`: Email password for SMTP

Example with custom environment variables:

```bash
docker run -p 8080:8080 \
  -e SPRING_DATASOURCE_URL=jdbc:mysql://your-db-host:3306/zm_data_base \
  -e SPRING_DATASOURCE_USERNAME=your-username \
  -e SPRING_DATASOURCE_PASSWORD=your-password \
  -e GOOGLE_CLIENT_ID=your-google-client-id \
  -e GOOGLE_CLIENT_SECRET=your-google-client-secret \
  -e FACEBOOK_CLIENT_ID=your-facebook-client-id \
  -e FACEBOOK_CLIENT_SECRET=your-facebook-client-secret \
  -e EMAIL_USERNAME=your-email@gmail.com \
  -e EMAIL_PASSWORD=your-email-password \
  zm-backend
```

## Local Development

For local development, you can run the application using Maven:

```bash
./mvnw spring-boot:run
```

## API Documentation

The API documentation is available at `/swagger-ui.html` when the application is running.