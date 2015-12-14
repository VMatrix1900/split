struct ssl_record {
    int server;
    size_t length;
    char *record;
};
