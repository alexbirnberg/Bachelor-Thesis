#include <stdio.h>
#include <stdint.h>
#include <curl/curl.h>

#define FTP_URL "ftp://192.168.100.132/big.bin"
#define DESTINATION_FILE "./big.bin"
#define USERNAME "user"
#define PASSWORD "p4ssw0rd."

uint64_t get_rtdsc()
{
    uint64_t tick1;
    unsigned c, d;

    asm volatile("rdtsc" : "=a" (c), "=d" (d));

    tick1 = (((uint64_t)c) | (((uint64_t)d) << 32));

    return tick1;
}

int main() {
    CURL *curl;
    CURLcode res;
    FILE *fp;
    uint64_t tstart, tend;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();
    if(curl) {
        fp = fopen(DESTINATION_FILE, "wb");
        if(fp) {
            curl_easy_setopt(curl, CURLOPT_URL, FTP_URL);
            /* Define our callback to get called when there's data to be written */
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, NULL);
            /* Set a pointer to our struct to pass to the callback */
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

            /* Set username and password for FTP authentication */
            curl_easy_setopt(curl, CURLOPT_USERNAME, USERNAME);
            curl_easy_setopt(curl, CURLOPT_PASSWORD, PASSWORD);

            tstart = get_rtdsc();

            res = curl_easy_perform(curl);

            tend = get_rtdsc();

            /* Check for errors */
            if(res != CURLE_OK)
                fprintf(stderr, "curl_easy_perform() failed: %s\n",
                        curl_easy_strerror(res));
            
            fclose(fp);
        } else {
            fprintf(stderr, "Failed to open %s\n", DESTINATION_FILE);
        }
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();

    printf("ticks: %ld\n", tend - tstart);

    return 0;
}