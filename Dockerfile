# Use Java 23 as the base image
FROM eclipse-temurin:23-jdk-alpine AS build

# Set the working directory
WORKDIR /app

# Copy Maven wrapper and POM file
COPY mvnw .
COPY .mvn .mvn
COPY pom.xml .

# Make the Maven wrapper executable
RUN chmod +x ./mvnw

# Download dependencies
RUN ./mvnw dependency:go-offline -B

# Copy the source code
COPY src ./src

# Build the application
RUN ./mvnw package -DskipTests

# Create a smaller runtime image
FROM eclipse-temurin:23-jre-alpine

# Set working directory
WORKDIR /app

# Copy the JAR file from the build stage
COPY --from=build /app/target/*.jar app.jar

# Expose the port the app runs on
EXPOSE 8080

# Set environment variables (these can be overridden at runtime)
ENV PORT=8080
ENV SPRING_DATASOURCE_URL=jdbc:mysql://7.tcp.eu.ngrok.io:11636/zm_data_base
ENV SPRING_DATASOURCE_USERNAME=root
ENV SPRING_DATASOURCE_PASSWORD=Rca/ocO/ips/m0

# Command to run the application
ENTRYPOINT ["java", "-jar", "app.jar"]