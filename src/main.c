#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>

#include "wiretap/wtap.h"
#include <cfile.h>
#include <epan/column.h>
#include <epan/epan.h>
#include <epan/epan_dissect.h>
#include <epan/ex-opt.h>
#include <epan/frame_data.h>
#include <epan/ftypes/ftypes.h>
#include <epan/ftypes/ftypes-int.h>
#include <epan/proto.h>
#include <epan/timestamp.h>
#include <epan/tvbuff.h>
#include <wsutil/privileges.h>

#define VERSION "0.1.0"

#define bool uint8_t
#define true 1
#define false 0
#define is_printable(a) ((unsigned)((a) - 0x20) <= 0x7e - 0x20)

typedef struct {
    bool print_filename;
    bool print_pkt;
    bool print_tuple;
    int  match_len;
    char* filename;
} Config;

void print_usage(int argc, char* argv[]);
void print_version(int argc, char* argv[]);
void scan_file(Config* config);

int main(int argc, char* argv[]) {
    int opt;
    int option_index = 0;

    Config config;
    config.print_filename = false;
    config.print_pkt = false;
    config.print_tuple = false;
    config.match_len = 4;
    config.filename = "-";

    static struct option long_options[] = {
        {"print-filename",      no_argument,       0, 'p'},
        {"print-packet-number", no_argument,       0, 'l'},
        {"print-five-tuple",    no_argument,       0, 'f'},
        {"bytes",               required_argument, 0, 'n'},
        {"help",                no_argument,       0, 'h'},
        {"version",             no_argument,       0, 'v'},
        {0,                     0,                 0,  0 }
    };

    while ((opt = getopt_long(argc, argv, "plfn:hv", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'p':
                config.print_filename = true;
                break;
            case 'l':
                config.print_pkt = true;
                break;
            case 'f':
                config.print_tuple = true;
                break;
            case 'n':
                config.match_len = atoi(optarg);
                break;
            case 'v':
                print_version(argc, argv);
            default:
                print_usage(argc, argv);
        }
    }

    timestamp_set_type(TS_RELATIVE);
    timestamp_set_precision(TS_PREC_AUTO);
    timestamp_set_seconds_type(TS_SECONDS_DEFAULT);

    init_process_policies();
    relinquish_special_privs_perm();
    wtap_init(true);

    // Initialise the Ethereal Protocol ANalyzer (EPAN)
    if(!epan_init(register_all_protocols, register_all_protocol_handoffs, NULL, NULL)) {
        fprintf(stderr, "epan_init failed\n");
        exit(EXIT_FAILURE);
    }

    if (optind < argc) {
        while (optind < argc) {
            config.filename = argv[optind++];
            scan_file(&config);
        }
    } else {
        scan_file(&config);
    }

    exit(EXIT_SUCCESS);
}

void print_usage(int argc, char* argv[]) {
    fprintf(stderr, "Usage: %s [option(s)] [pcap(s)]\n", argv[0]);
    fprintf(stderr, "Display printable strings in [pcap(s)] (stdin by default)\n");
    fprintf(stderr, "The options are:\n");
    fprintf(stderr, "  -p --print-filename      Print the filename before the string\n");
    fprintf(stderr, "  -l --print-packet-number Print the number of the packet before the string\n");
    fprintf(stderr, "  -f --print-five-tuple    Print the five tuple of the match before the string\n");
    fprintf(stderr, "  -n --bytes=[number]      Locate & print any NUL-terminated sequence of at least\n");
    fprintf(stderr, "                           [number] characters (default 4)\n");
    fprintf(stderr, "  -h --help                Display this information\n");
    fprintf(stderr, "  -v --version             Print the program's version number\n");

    exit(EXIT_FAILURE);
}

void print_version(int argc, char* argv[]) {
    fprintf(stderr, "%s: %s\n", argv[0], VERSION);

    exit(EXIT_SUCCESS);
}

void scan_file(Config* config) {
    int wtap_errno;
    gchar* wtap_errstr;

    wtap_opttypes_initialize();
    struct wtap* wth = wtap_open_offline(config->filename, WTAP_TYPE_AUTO, &wtap_errno, &wtap_errstr, true);

    if (wth == NULL) {
        fprintf(stderr, "There was an error opening the file '%s' (error %d)\n", config->filename, wtap_errno);

        if (wtap_errstr != NULL) {
            fprintf(stderr, "%s\n", wtap_errstr);
        }

        exit(EXIT_FAILURE);
    }

    // Create a capture file
    capture_file cf;
    wtap_rec* rec;

    static const struct packet_provider_funcs funcs = {
        NULL,
    };
    epan_t* epan = epan_new(&cf.provider, &funcs);
    cf.epan = epan;

    cf.cum_bytes = 0;
    cf.provider.wth = wth;
    cf.f_datalen = 0;
    cf.filename = g_strdup(config->filename);
    cf.is_tempfile = false;
    cf.unsaved_changes = false;
    cf.cd_t = wtap_file_type_subtype(wth);
    cf.open_type = WTAP_TYPE_AUTO;
    cf.count = 0;
    cf.drops_known = false;
    cf.drops = 0;
    cf.snap = wtap_snapshot_length(wth);
    nstime_set_zero(&cf.elapsed_time);
    cf.provider.ref = NULL;
    cf.provider.prev_dis = NULL;
    cf.provider.prev_cap = NULL;
    cf.provider.frames = new_frame_data_sequence();
    cf.state = FILE_READ_IN_PROGRESS;

    /*
     * Col 1 = Index
     * Col 2 = Timestamp
     * Col 3 = Source IP
     * Col 4 = Destination IP
     * Col 5 = Protocol
     * Col 6 = Frame Length
     * Col 7 = Description
     */
    build_column_format_array(&cf.cinfo, 5, true);

    /* 2nd param => generate_tree, 3rd => print results */
    epan_dissect_t* edt = epan_dissect_new(epan, false, false);

    int64_t offset;
    while (wtap_read(cf.provider.wth, &wtap_errno, &wtap_errstr, &offset)) {
        rec = wtap_get_rec(cf.provider.wth);

        const uint8_t* data = wtap_get_buf_ptr(cf.provider.wth);
        tvbuff_t* buffer = tvb_new_real_data(data, rec->rec_header.packet_header.caplen, rec->rec_header.packet_header.len);

        cf.count++;

        char tuple[33];

        if (config->print_tuple) {
            frame_data fdata;
            frame_data_init(&fdata, cf.count, rec, offset, cf.cum_bytes);
            frame_data_set_before_dissect(&fdata, &cf.elapsed_time, &cf.provider.ref, cf.provider.prev_dis);

            epan_dissect_run(edt, cf.cd_t, rec, buffer, &fdata, &cf.cinfo);
            epan_dissect_fill_in_columns(edt, false, true);

            sprintf(tuple, "%-15s %-15s ", cf.cinfo.columns[2].col_data, cf.cinfo.columns[3].col_data);

            frame_data_set_after_dissect(&fdata, &cf.cum_bytes);
            cf.provider.prev_cap = cf.provider.prev_dis = frame_data_sequence_add(cf.provider.frames, &fdata);

            epan_dissect_reset(edt);
            frame_data_destroy(&fdata);
        }

        // Search for strings
        uint8_t byte = 0;
        int count = 0;
        char str[config->match_len + 1];

        for (uint32_t i = 0; i < rec->rec_header.packet_header.len; ++i, byte = data[i]) {
            if (is_printable(byte) || byte == '\t') {
                if (count > config->match_len) {
                    printf("%c", byte);
                } else {
                    str[count] = byte;

                    if (count == config->match_len) {
                        if (config->print_filename) {
                            printf("%s ", cf.filename);
                        }

                        if (config->print_pkt) {
                            printf("%04d ", cf.count);
                        }

                        if (config->print_tuple) {
                            printf("%s", tuple);
                        }

                        str[count + 1] = 0;
                        printf("%s", str);
                    }

                    count++;
                }
            } else {
                if (count > config->match_len) {
                    printf("\n");
                }

                count = 0;
            }
        }

        // Catch the case at the end of the packet
        if (count > config->match_len) {
            printf("\n");
        }
    }

    epan_dissect_free(edt);
    epan_free(epan);
    epan_cleanup();
}
