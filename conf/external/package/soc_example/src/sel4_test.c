#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "ree_tee_msg.h"

#define SECURE 0
#define PLAIN  1

#define SEL4TEE "/dev/sel4com"

static uint8_t tmp_key[] = {0x76, 0xa4, 0x58, 0xd1, 0x0e, 0xd7, 0xc0, 0x9b, 0xf5, 0x0d, 0xd2, 0xb9};

static uint8_t test_data[] = {
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xCA, 0xFE, 0xAB, 0xBA, 0xCD,
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xCA, 0xFE, 0xAB, 0xBA, 0xCD,
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xCA, 0xFE, 0xAB, 0xBA, 0xCD,
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xCA, 0xFE, 0xAB, 0xBA, 0xCD,
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xCA, 0xFE, 0xAB, 0xBA, 0xCD,
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xCA, 0xFE, 0xAB, 0xBA, 0xCD,
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xCA, 0xFE, 0xAB, 0xBA, 0xCD,
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xCA, 0xFE, 0xAB, 0xBA, 0xCD,
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xCA, 0xFE, 0xAB, 0xBA, 0xCD,
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xCA, 0xFE, 0xAB, 0xBA, 0xCD,
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xCA, 0xFE, 0xAB, 0xBA, 0xCD,
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xCA, 0xFE, 0xAB, 0xBA, 0xCD,
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xCA, 0xFE, 0xAB, 0xBA, 0xCD,
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xCA, 0xFE, 0xAB, 0xBA, 0xCD,
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xCA, 0xFE, 0xAB, 0xBA, 0xCD,
0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xCA, 0xFE, 0xCA, 0xFE, 0xAB, 0xBA, 0xFF
};


//#define SEL4TEE "/dev/null"

static void print_menu(void)
{
    printf("\n\nWelcome seL4 test application\n");
    printf("Select:\n");
    printf("0 - Exit\n");
    printf("1 - Random number from sel4 TEE\n");
    printf("2 - Write data to sNVM\n");
    printf("3 - Read Data from sNVM\n");
    printf("4 - Device serial number\n");
    printf("5 - PUF demo\n");
    printf("\n");
}

static int handle_snvm_write(uint8_t *input_data, uint8_t *key, int handle, int page, int mode)
{
    ssize_t ret;
    struct ree_tee_snvm_cmd cmd = {0};

    /* Open binary file for input data*/
    if((!input_data) || (!handle) || (!key)){
        return -EINVAL;
    }

    cmd.msg_type = REE_TEE_SNVM_WRITE_REQ;
    /*
     * Length here means how much we are goint to write data, for secure
     * write we send 236 bytes and for plaintext 252 bytes
     */
    if (mode == PLAIN) {
        cmd.length = 252;
    } else if (mode == SECURE) {
        cmd.length = 236;
    } else {
        printf("Invalid mode\n");
        return -EINVAL;
    }
    cmd.page_number = page;
    memcpy(cmd.user_key, key, USER_KEY_LENGTH );
    memcpy(cmd.data, input_data, cmd.length);

    /*Write message to TEE*/
    ret = write(handle, &cmd, sizeof(cmd));
    if (ret != sizeof(cmd))
    {
        printf("Writing snvm write request failed\n");
        return -EIO;
    }

    do {
        ret = read(handle, &cmd, sizeof(cmd));
    } while (ret < 0);

    if (ret != sizeof(cmd))
    {
        printf("Reading snvm write response failed: %lu \n", ret);
        return -EIO;
    }
    return 0;
}

static int handle_snvm_read(int handle, int page, uint8_t *key, uint8_t *output, int mode)
{

    ssize_t ret;
    struct ree_tee_snvm_cmd cmd = {0};

    cmd.msg_type = REE_TEE_SNVM_READ_REQ;

    /*
     * Length here means how much we are goint to read data, for secure
     * read we request 236 bytes and for plaintext 252 bytes
     */
    if (mode == PLAIN) {
        cmd.length = 252;
    } else if (mode == SECURE) {
        cmd.length = 236;
    } else {
        printf("Invalid mode\n");
        return -EINVAL;
    }
    cmd.page_number = page;
    memcpy(cmd.user_key, key, USER_KEY_LENGTH );

    ret = write(handle, &cmd, sizeof(cmd));
    if (ret != sizeof(cmd))
    {
        printf("Writing snvm read request failed\n");
        return -EIO;
    }

    do {
        ret = read(handle, &cmd, sizeof(cmd));
    } while (ret < 0);

    if (ret != sizeof(cmd))
    {
        printf("Reading snvm read response failed: %lu \n", ret);
        return -EIO;
    }
    if (output)
    {
        /* response data buffer is 252 bytes but actual data can be 236 or 252 bytes */
        memcpy(output, cmd.data, cmd.length);
    }
    else
    {
        printf("\nsNVM page %d data:", page);
        for(int i = 0; i < cmd.length; i++) {
            printf("%2.2x ", cmd.data[i]);
        }
    }
    return 0;
}

static int handle_puf_request(int handle, uint8_t opcode, uint8_t *challenge, uint8_t *output)
{
    ssize_t ret;
    struct ree_tee_puf_cmd cmd = {0};

    cmd.msg_type = REE_TEE_PUF_REQ;
    cmd.length = sizeof(cmd);
    cmd.opcode = opcode;
    memcpy(cmd.request, challenge, PUF_CHALLENGE );

    ret = write(handle, &cmd, sizeof(cmd));
    if (ret != sizeof(cmd))
    {
        printf("Writing puf request failed\n");
        return -EIO;
    }

    do {
        ret = read(handle, &cmd, sizeof(cmd));
    } while (ret < 0);

    if (ret != sizeof(cmd))
    {
        printf("Reading puf response failed: %lu \n", ret);
        return -EIO;
    }

    if (output)
    {
        memcpy(output, cmd.response, PUF_RESPONSE);
    }
    else
    {
        printf("\nPUF data:");
        for(int i = 0; i < PUF_RESPONSE; i++) {
            printf("%2.2x ", cmd.response[i]);
        }
    }
    return 0;

}

static int handle_deviceid_request(int f, uint8_t *output)
{
    ssize_t ret;
    struct ree_tee_deviceid_cmd cmd ={
        .msg_type = REE_TEE_DEVICEID_REQ,
    };

    /*Write message to TEE*/
    ret = write(f, &cmd, sizeof(cmd));
    if (ret != sizeof(cmd))
    {
        printf("Writing deviceid request failed\n");
        return -EIO;
    }

    /*Read Response , polling*/
    do {
        ret = read(f, &cmd, sizeof(cmd));
    } while (ret < 0);

    if (ret != sizeof(cmd))
    {
        printf("Reading device id message failed: %lu \n", ret);
        return -EIO;
    }

    if (output)
    {
        memcpy(output, cmd.response, DEVICE_ID_LENGTH);
    }
    else
    {
        /* print value*/
        printf("\nDeviceID: ");
        for(int i = 0; i < DEVICE_ID_LENGTH; i++) {
            printf("%2.2x", cmd.response[i]);
        }
    }

    return 0;
}

static int handle_rng_request(int f, uint8_t *output)
{
    ssize_t ret;

    struct ree_tee_rng_cmd cmd ={
        .msg_type = REE_TEE_RNG_REQ,
    };

    /*Write message to TEE*/
    ret = write(f, &cmd, sizeof(cmd));
    if (ret != sizeof(cmd))
    {
        printf("Writing rng request failed\n");
        return -EIO;
    }

    /*Read Response , polling*/
    do {
        ret = read(f, &cmd, sizeof(cmd));
    } while (ret < 0);

    if (ret != sizeof(cmd))
    {
        printf("Reading rng message failed: %lu \n", ret);
        return -EIO;
    }
    if (output)
    {
        memcpy(output, cmd.response, RNG_SIZE_IN_BYTES);
    }
    else
    {
        /* print value*/
        printf("\nRNG value:");
        for(int i = 0; i < RNG_SIZE_IN_BYTES; i++) {
            printf("%2.2x ", cmd.response[i]);
        }
    }
    return 0;
}

int main(void)
{
    int f;
    int choice;
    int i = 1;
    int page = 0;
    int ret = 0;
    int mode = 0;
    f = open(SEL4TEE, O_RDWR);
    if(!f)
    {
        printf("failed to open %s\n", SEL4TEE);
        return -EIO;
    }
    while (i)
    {
        print_menu();
        scanf("%d", &choice);

        switch (choice)
        {
        case 0:
            i = 0;
            break;
        case 1:
                ret = handle_rng_request(f, NULL);
            break;
        case 2:
            printf("\nEnter page to write: ");
            scanf("%d", &page);
            printf("\nEnter mode (1 PLAIN, 0 SECURE): ");
            scanf("%d", &mode);
            ret = handle_snvm_write(test_data, tmp_key, f, page, mode);
        break;
        case 3:
            printf("\nEnter page to read: ");
	        scanf("%d", &page);
            printf("\nEnter mode (1 PLAIN, 0 SECURE): ");
            scanf("%d", &mode);
            ret = handle_snvm_read(f, page, tmp_key, NULL, mode);
        break;
        case 4:
            ret = handle_deviceid_request(f, NULL);
        break;
        case 5:
        {
            uint8_t puf_challenge[PUF_CHALLENGE];
            printf("\nEnter opcode for PUF: ");
	        scanf("%d", &page);
            /*set device serial as puf challenge*/
            ret = handle_deviceid_request(f,puf_challenge);
            if (ret)
                break;

            ret = handle_puf_request(f, page, puf_challenge, NULL);

        }
        default:
            break;
        }
    }


return ret;

}
