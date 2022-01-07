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

#define HDR_LEN     sizeof(struct ree_tee_hdr)

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

static uint8_t tmp_hash [] = {
0x74, 0xf0, 0xdb, 0x99, 0x7d, 0xd3, 0x5a, 0xe9, 0x65, 0xab, 0x39, 0x74, 0x2e, 0x76, 0xf9, 0x30,
0x20, 0x74, 0x11, 0xe5, 0xc6, 0x74, 0x26, 0x2f, 0xe4, 0xcc, 0xae, 0x53, 0xec, 0x0c, 0x2f, 0xac,
0x65, 0x24, 0xd0, 0x41, 0x9a, 0x34, 0x2b, 0x60, 0xb6, 0x76, 0xc0, 0x03, 0xaa, 0x2d, 0xf9, 0xbb
};

//#define SEL4TEE "/dev/null"

static void print_menu(void)
{
    printf("\n\nBuild Date %s Time %s", __DATE__, __TIME__);
    printf("\n\nWelcome seL4 test application\n");
    printf("Select:\n");
    printf("0 - Exit\n");
    printf("1 - Random number from sel4 TEE\n");
    printf("2 - Write data to sNVM\n");
    printf("3 - Read Data from sNVM\n");
    printf("4 - Device serial number\n");
    printf("5 - PUF demo\n");
    printf("6 - seL4 status\n");
    printf("7 - Unknown msg type\n");
    printf("8 - Sign Service\n");
    printf("9 - Generate keys\n");
    printf("10 - Generate key and extract public key");
    printf("\n");
}

static int handle_unknown_request(int handle)
{
    ssize_t ret;

    struct ree_tee_status_req cmd = {
        .hdr.msg_type = INVALID,
        .hdr.length = HDR_LEN,
    };

    /*Write message to TEE*/
    ret = write(handle, &cmd, cmd.hdr.length);
    if (ret != cmd.hdr.length)
    {
        printf("Writing status request failed\n");
        return -EIO;
    }

    /*Read Response, polling*/
    do {
        ret = read(handle, &cmd, HDR_LEN);
    } while (ret < 0);

    if (ret != HDR_LEN)
    {
        printf("Reading status message failed: %lu \n", ret);
        return -EIO;
    }

    printf("msg status: %d\n", cmd.hdr.status);

    return 0;
}

static int handle_status_request(int handle)
{
    ssize_t ret;

    struct ree_tee_status_req cmd = {
        .hdr.msg_type = REE_TEE_STATUS_REQ,
        .hdr.length = HDR_LEN,
    };

    /*Write message to TEE*/
    ret = write(handle, &cmd, cmd.hdr.length);
    if (ret != cmd.hdr.length)
    {
        printf("Writing status request failed\n");
        return -EIO;
    }

    /*Read Response, polling*/
    do {
        ret = read(handle, &cmd, HDR_LEN);
    } while (ret < 0);

    if (ret != HDR_LEN)
    {
        printf("Reading status message failed: %lu \n", ret);
        return -EIO;
    }

    printf("msg status: %d\n", cmd.hdr.status);

    return 0;
}

static int handle_snvm_write(uint8_t *input_data, uint8_t *key, int handle, int page, int mode)
{
    ssize_t ret;
    struct ree_tee_snvm_cmd cmd = {
        .hdr.msg_type = REE_TEE_SNVM_WRITE_REQ,
        .hdr.length = sizeof(struct ree_tee_snvm_cmd),
    };

    /* Open binary file for input data*/
    if((!input_data) || (!handle) || (!key)){
        return -EINVAL;
    }

    /*
     * Length here means how much we are goint to write data, for secure
     * write we send 236 bytes and for plaintext 252 bytes
     */
    if (mode == PLAIN) {
        cmd.snvm_length = 252;
    } else if (mode == SECURE) {
        cmd.snvm_length = 236;
    } else {
        printf("Invalid mode\n");
        return -EINVAL;
    }
    cmd.page_number = page;
    memcpy(cmd.user_key, key, USER_KEY_LENGTH );
    memcpy(cmd.data, input_data, cmd.snvm_length);

    /*Write message to TEE*/
    ret = write(handle, &cmd, cmd.hdr.length);
    if (ret != cmd.hdr.length)
    {
        printf("Writing snvm write request failed\n");
        return -EIO;
    }

    do {
        ret = read(handle, &cmd, HDR_LEN);
    } while (ret < 0);

    if (ret != HDR_LEN)
    {
        printf("Reading snvm write response failed: %lu \n", ret);
        return -EIO;
    }
    return 0;
}

static int handle_snvm_read(int handle, int page, uint8_t *key, uint8_t *output, int mode)
{

    ssize_t ret;
    struct ree_tee_snvm_cmd cmd = {
        .hdr.msg_type = REE_TEE_SNVM_READ_REQ,
        .hdr.length = sizeof(struct ree_tee_snvm_cmd),
    };

    /*
     * Length here means how much we are goint to read data, for secure
     * read we request 236 bytes and for plaintext 252 bytes
     */
    if (mode == PLAIN) {
        cmd.snvm_length = 252;
    } else if (mode == SECURE) {
        cmd.snvm_length = 236;
    } else {
        printf("Invalid mode\n");
        return -EINVAL;
    }
    cmd.page_number = page;
    memcpy(cmd.user_key, key, USER_KEY_LENGTH );

    ret = write(handle, &cmd, cmd.hdr.length);
    if (ret != cmd.hdr.length)
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
        memcpy(output, cmd.data, cmd.snvm_length);
    }
    else
    {
        printf("\nsNVM page %d data:", page);
        for(int i = 0; i < cmd.snvm_length; i++) {
            printf("%2.2x ", cmd.data[i]);
        }
    }
    return 0;
}

static int handle_puf_request(int handle, uint8_t opcode, uint8_t *challenge, uint8_t *output)
{
    ssize_t ret;
    struct ree_tee_puf_cmd cmd = {
        .hdr.msg_type = REE_TEE_PUF_REQ,
        .hdr.length = sizeof(struct ree_tee_puf_cmd),
        .opcode = opcode,
    };

    memcpy(cmd.request, challenge, PUF_CHALLENGE );

    ret = write(handle, &cmd, cmd.hdr.length);
    if (ret != cmd.hdr.length)
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

static int handle_sign_request(int handle, uint8_t format, uint8_t *hash, uint8_t *output)
{
    ssize_t ret;
    struct ree_tee_sign_cmd cmd = {
        .hdr.msg_type = REE_TEE_SIGN_REQ,
        .hdr.length = sizeof(struct ree_tee_sign_cmd),
        .format = format,
    };

    memcpy(cmd.hash, hash, HASH_LENGTH );

    ret = write(handle, &cmd, cmd.hdr.length);
    if (ret != cmd.hdr.length)
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
        memcpy(output, cmd.response, SIGN_RESP_LENGTH);
    }
    else
    {
        printf("\nSigned data:");
        for(int i = 0; i < SIGN_RESP_LENGTH; i++) {
            printf("%2.2x ", cmd.response[i]);
        }
    }
    return 0;

}

static int handle_deviceid_request(int f, uint8_t *output)
{
    ssize_t ret;
    struct ree_tee_deviceid_cmd cmd ={
        .hdr.msg_type = REE_TEE_DEVICEID_REQ,
        .hdr.length = HDR_LEN,
    };

    /*Write message to TEE*/
    ret = write(f, &cmd, cmd.hdr.length);
    if (ret != cmd.hdr.length)
    {
        printf("Writing deviceid request failed\n");
        return -EIO;
    }

    /*Read Response, polling*/
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
        .hdr.msg_type = REE_TEE_RNG_REQ,
        .hdr.length = HDR_LEN,
    };

    /*Write message to TEE*/
    ret = write(f, &cmd, cmd.hdr.length);
    if (ret != cmd.hdr.length)
    {
        printf("Writing rng request failed\n");
        return -EIO;
    }

    /*Read Response, polling*/
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


static int handle_key_creation_request(int f, uint32_t format, uint32_t nbits, const char *name, uint8_t *output, uint32_t *ouput_len)
{
    ssize_t ret;
    int i;
    uint8_t resp[4096];

    struct ree_tee_key_resp_cmd *ret_cmd;
    struct ree_tee_key_req_cmd cmd ={
        .hdr.msg_type = REE_TEE_GEN_KEY_REQ,
        .hdr.length = sizeof(struct ree_tee_key_req_cmd ),
        .key_req_info.format = format,
        .key_req_info.key_nbits = nbits,
    };

    strcpy(cmd.key_req_info.name, name);

    /*Write message to TEE*/
    ret = write(f, &cmd, cmd.hdr.length);
    if (ret != cmd.hdr.length)
    {
        printf("Writing key pair request failed\n");
        return -EIO;
    }

    /*Read Response, polling*/
    do {
        ret = read(f, resp, sizeof(resp));
    } while (ret < 0);

    ret_cmd = (struct ree_tee_key_resp_cmd*)resp;

    printf("Pub Key length = %d, priv key length = %d", ret_cmd->key_data_info.pubkey_length, ret_cmd->key_data_info.privkey_length);

    uint8_t *public_key = &ret_cmd->key_data.keys[0];
    uint8_t *private_key = &ret_cmd->key_data.keys[ret_cmd->key_data_info.pubkey_length];


    if (output)
    {
        printf("Storage blob size = %d\n", ret_cmd->key_data.storage_size);
        memcpy(output, &ret_cmd->key_data, ret_cmd->key_data.storage_size);
        *ouput_len = ret_cmd->key_data.storage_size;


    }
    else
    {
        for  (i = 0; i <  ret_cmd->key_data_info.pubkey_length ; i++)
        {
            printf("PubKey[%d] = 0x%x\n",i, public_key[i]);
        }

        for (i = 0; i < ret_cmd->key_data_info.privkey_length ; i++)
        {
            printf("PrivateKey[%d] = 0x%x\n",i, private_key[i]);
        }
    }

    return 0;
}

static int handle_publick_key_extraction_request(int f, uint8_t *key_blob, uint32_t blob_size, uint32_t clientid, uint8_t *guid, uint32_t *nbits,  uint8_t *output, uint32_t *pubkey_len)
{
    ssize_t ret;
    int i;
    uint8_t buf[4096] = {0};

    struct ree_tee_pub_key_resp_cmd *ret_cmd;
    struct ree_tee_pub_key_req_cmd *cmd = (struct ree_tee_pub_key_req_cmd *)buf;


    cmd->hdr.msg_type = REE_TEE_EXT_PUBKEY_REQ;
    cmd->hdr.length = sizeof(struct ree_tee_pub_key_req_cmd) + blob_size;
    cmd->client_id = clientid;

    memcpy(&cmd->crypted_key_data[0], key_blob, blob_size);
    memcpy(cmd->guid, guid, 32);

    /*Write message to TEE*/
    ret = write(f, buf, cmd->hdr.length);
    if (ret != cmd->hdr.length)
    {
        printf("Writing public key request failed\n");
        return -EIO;
    }

    /*Read Response, polling*/
    do {
        ret = read(f, buf, sizeof(buf));
    } while (ret < 0);

     ret_cmd = (struct ree_tee_pub_key_resp_cmd*)buf;

     printf("Publick key data Name = %s Length = %d\n", ret_cmd->key_info.name, ret_cmd->key_info.pubkey_length);

    if (output) {
        memcpy(output, &ret_cmd->pubkey, ret_cmd->key_info.pubkey_length);
        *nbits = ret_cmd->key_info.key_nbits;
        *pubkey_len = ret_cmd->key_info.pubkey_length;
    } else {
        uint8_t *public_key = &ret_cmd->pubkey[0];
        for  (i = 0; i <  ret_cmd->key_info.pubkey_length ; i++)
        {
            printf("PubKey[%d] = 0x%x\n",i, public_key[i]);
        }

    }

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
        break;
        case 6:
            ret = handle_status_request(f);
        break;
        case 7:
            ret = handle_unknown_request(f);
        break;
        case 8:
        {
            int format;
            printf("\nEnter format (1 RAW, 0 DER): ");
            scanf("%d", &format);
            if (format)
                handle_sign_request(f, RAW_FORMAT, tmp_hash, NULL);
            else
                handle_sign_request(f, DER_FORMAT, tmp_hash, NULL);
        }
        break;
        case 9:
            ret =  handle_key_creation_request(f, KEY_RSA, 3072, "Kekkonen", NULL, NULL);
        break;
        case 10:
        {
            uint8_t key_data[4096];
            uint8_t guid[32] = {0};
            uint32_t nbits;
            uint32_t key_data_len;
            ret =  handle_key_creation_request(f, KEY_RSA, 3072, "Krypt_test", key_data, &key_data_len);
            printf("Key blob size = %d\n", key_data_len);
            if (!ret)
            {
                handle_publick_key_extraction_request(f, key_data, key_data_len, 0, guid, &nbits, NULL, NULL);
            }

        }
        default:
        break;
        }
    }


return ret;

}
