// helpless HTTP daemon

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define PORT 8080
#define HTTP200 "HTTP/1.1 200 OK"
#define HTTP400 "HTTP/1.1 400 Bad Request"
#define CTYPE   "Content-Type: text/plain"
#define CLENGTH "Content-Length: "

/* Initializes the socket and returns its file descriptor. */
int setup()
{
    // create socket file descriptor
    int server_fd;
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // allow quick regaining ownership of the socket on restart
    const int on = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &on, sizeof(on))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(PORT);

    // start listening to any address
    if (bind(server_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    return server_fd;
}

/* Accepts an incoming connection and returns the file descriptor of the client socket. */
int recv_request(int server_fd)
{
    int client_fd;
    struct sockaddr_in client_addr;
    int addrlen = sizeof(client_addr);

    if ((client_fd = accept(server_fd, (struct sockaddr*)&client_addr, (socklen_t*)&addrlen)) < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }
    printf("Request from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
    return client_fd;
}

/* Returns an HTTP 200 response with a greeting. */
char* good_request(char* buffer, int i)
{
    const unsigned short msgsize = strlen("Hello, !\n") + i;
    char msg[64] = "Hello, ";

    const int rsize = strlen(HTTP200) + strlen(CTYPE) + strlen(CLENGTH) + sizeof(
            unsigned short) + msgsize + 9; // 9 = 4*(\n\r) + 1*\0
    char* reply = malloc(rsize);
    if (!reply) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    snprintf(reply, rsize, "%s\r\n%s\r\n%s%hu\r\n\r\n", HTTP200, CTYPE, CLENGTH, msgsize);
    strncpy(msg + strlen(msg), buffer, i);
    strncpy(msg + strlen(msg), "!\n", 3);
    memcpy(reply + strlen(reply), msg, strlen(msg) + 1);
    return reply;
}

/* Returns an empty HTTP 400 response. */
char* bad_request()
{
    const int rsize = strlen(HTTP400) + 3; // 3 = \n\r\0
    char* reply = malloc(rsize);

    if (!reply) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    strncpy(reply, HTTP400 "\r\n", rsize);
    return reply;
}

/* Returns a response to the request from client_fd. */
char* handle_request(int client_fd)
{
    char name[64] = {0};
    char buffer[1024] = {0};
    char* reply;
    int offset = 5;
    int i = 0;

    read(client_fd, buffer, 1024);

    // parse the request
    if (strncmp(buffer, "GET", 3) == 0) {
        offset = 5;
        i = strcspn(buffer + offset, " "); // first occurrence of ' '
        if (i == strlen(buffer + offset)) { // not found
            reply = bad_request();
        } else if (i == 0) { // the request URL is /
            strcpy(name, "cruel world");
            reply = good_request(name, strlen(name));
        } else {
            reply = good_request(buffer + offset, i);
        }
    } else {
        // unsupported method
        reply = bad_request();
    }
    return reply;
}

/* Sends reply to client_fd. */
void send_reply(int client_fd, char* reply)
{
    if (send(client_fd, reply, strlen(reply), 0) < 0) {
        perror("send");
        exit(EXIT_FAILURE);
    }
    close(client_fd);
}

/* Entry point. */
int main()
{
    // daemonize
    int pid = fork();
    if (pid < 0) {
        fprintf(stderr, "Failed to become a daemon, running interactively.\n");
    } else if (pid > 0) {
        // parent
        printf("Just became a daemon with pid %d.\n", pid);
        return 0;
    }

    int server_fd = setup();
    while (1) {
        int client_fd = recv_request(server_fd);
        char* reply = handle_request(client_fd);
        send_reply(client_fd, reply);
        free(reply);
    }
    return 0;
}
