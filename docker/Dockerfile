# Start from the latest Golang base image
FROM golang:1.22

# Add Maintainer Info
LABEL maintainer="Renato Rosa <r.guima@yahoo.com.br>"

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY . .

# Build the Go app
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Expose port 8000 to the outside
EXPOSE 8000

# Command to run the executable
CMD ["./main"]