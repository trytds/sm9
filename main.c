#include<stdio.h>
#include "miracl.h"
#include "mirdef.h"
#include "sm9_standard.h"

int main()
{
    //the master private key
    unsigned char dA[32] = { 0x00, 0x01, 0x30, 0xE7, 0x84, 0x59, 0xD7, 0x85, 0x45, 0xCB, 0x54, 0xC5, 0x87, 0xE0, 0x2C, 0xF4,
                            0x80, 0xCE, 0x0B, 0x66, 0x34, 0x0F, 0x31, 0x9F, 0x34, 0x8A, 0x1D, 0x5B, 0x1F, 0x2D, 0xC5, 0xF4 };
    unsigned char rand[32] = { 0x00, 0x03, 0x3C, 0x86, 0x16, 0xB0, 0x67, 0x04, 0x81, 0x32, 0x03, 0xDF, 0xD0, 0x09, 0x65, 0x02,
                              0x2E, 0xD1, 0x59, 0x75, 0xC6, 0x62, 0x33, 0x7A, 0xED, 0x64, 0x88, 0x35, 0xDC, 0x4B, 0x1C, 0xBE };

    unsigned char h[32], S[64];// Signature
    unsigned char Ppub[128], dSA[64];

    unsigned char std_h[32] = { 0x82, 0x3C, 0x4B, 0x21, 0xE4, 0xBD, 0x2D, 0xFE, 0x1E, 0xD9, 0x2C, 0x60, 0x66, 0x53, 0xE9, 0x96,
                               0x66, 0x85, 0x63, 0x15, 0x2F, 0xC3, 0x3F, 0x55, 0xD7, 0xBF, 0xBB, 0x9B, 0xD9, 0x70, 0x5A, 0xDB };
    unsigned char std_S[64] = { 0x73, 0xBF, 0x96, 0x92, 0x3C, 0xE5, 0x8B, 0x6A, 0xD0, 0xE1, 0x3E, 0x96, 0x43, 0xA4, 0x06, 0xD8,
                               0xEB, 0x98, 0x41, 0x7C, 0x50, 0xEF, 0x1B, 0x29, 0xCE, 0xF9, 0xAD, 0xB4, 0x8B, 0x6D, 0x59, 0x8C,
                               0x85, 0x67, 0x12, 0xF1, 0xC2, 0xE0, 0x96, 0x8A, 0xB7, 0x76, 0x9F, 0x42, 0xA9, 0x95, 0x86, 0xAE,
                               0xD1, 0x39, 0xD5, 0xB8, 0xB3, 0xE1, 0x58, 0x91, 0x82, 0x7C, 0xC2, 0xAC, 0xED, 0x9B, 0xAA, 0x05 };
    unsigned char std_Ppub[128] = { 0x9F, 0x64, 0x08, 0x0B, 0x30, 0x84, 0xF7, 0x33, 0xE4, 0x8A, 0xFF, 0x4B, 0x41, 0xB5, 0x65, 0x01,
                                   0x1C, 0xE0, 0x71, 0x1C, 0x5E, 0x39, 0x2C, 0xFB, 0x0A, 0xB1, 0xB6, 0x79, 0x1B, 0x94, 0xC4, 0x08,
                                   0x29, 0xDB, 0xA1, 0x16, 0x15, 0x2D, 0x1F, 0x78, 0x6C, 0xE8, 0x43, 0xED, 0x24, 0xA3, 0xB5, 0x73,
                                   0x41, 0x4D, 0x21, 0x77, 0x38, 0x6A, 0x92, 0xDD, 0x8F, 0x14, 0xD6, 0x56, 0x96, 0xEA, 0x5E, 0x32,
                                   0x69, 0x85, 0x09, 0x38, 0xAB, 0xEA, 0x01, 0x12, 0xB5, 0x73, 0x29, 0xF4, 0x47, 0xE3, 0xA0, 0xCB,
                                   0xAD, 0x3E, 0x2F, 0xDB, 0x1A, 0x77, 0xF3, 0x35, 0xE8, 0x9E, 0x14, 0x08, 0xD0, 0xEF, 0x1C, 0x25,
                                   0x41, 0xE0, 0x0A, 0x53, 0xDD, 0xA5, 0x32, 0xDA, 0x1A, 0x7C, 0xE0, 0x27, 0xB7, 0xA4, 0x6F, 0x74,
                                   0x10, 0x06, 0xE8,0x5F,0x5C,0xDF,0xF0,0x73,0x0E,0x75,0xC0,0x5F,0xB4,0xE3,0x21, 0x6D };
    unsigned char std_dSA[64] = { 0xA5, 0x70, 0x2F, 0x05, 0xCF, 0x13, 0x15, 0x30, 0x5E, 0x2D, 0x6E, 0xB6, 0x4B, 0x0D, 0xEB, 0x92,
                                 0x3D, 0xB1, 0xA0, 0xBC, 0xF0, 0xCA, 0xFF, 0x90, 0x52, 0x3A, 0xC8, 0x75, 0x4A, 0xA6, 0x98, 0x20,
                                 0x78, 0x55, 0x9A, 0x84, 0x44, 0x11, 0xF9, 0x82, 0x5C, 0x10, 0x9F, 0x5E, 0xE3, 0xF5, 0x2D, 0x72,
                                 0x0D, 0xD0, 0x17, 0x85, 0x39, 0x2A, 0x72, 0x7B, 0xB1, 0x55, 0x69, 0x52, 0xB2, 0xB0, 0x13, 0xD3 };

    unsigned char hid[] = { 0x01 };
    unsigned char* IDA = "Alice";
    unsigned char* message = "Chinese IBS standard";//the message to be signed
    int mlen = strlen(message), tmp;//the length of message
    big ks;

    tmp = SM9_standard_init();

    if (tmp != 0)
        return tmp;
    ks = mirvar(0);

    bytes_to_big(32, dA, ks);

    printf("\n*********************** SM9 key Generation ***************************\n");
    tmp = SM9_standard_generatesignkey(hid, IDA, strlen(IDA), ks, Ppub, dSA);
    if (tmp != 0)
        return tmp;
    if (memcmp(Ppub, std_Ppub, 128) != 0)
        return SM9_GEPUB_ERR;
    if (memcmp(dSA, std_dSA, 64) != 0)
        return SM9_GEPRI_ERR;

    printf("\n********************** SM9 signature algorithm***************************\n");
    tmp = SM9_standard_sign(hid, IDA, message, mlen, rand, dSA, Ppub, h, S);
    if (tmp != 0)
        return tmp;
    if (memcmp(h, std_h, 32) != 0)
        return SM9_SIGN_ERR;
    if (memcmp(S, std_S, 64) != 0)
        return SM9_SIGN_ERR;
    
    printf("\n******************* SM9 verification algorithm *************************\n");
    tmp = SM9_standard_verify(h, S, hid, IDA, message, mlen, Ppub);
    if (tmp != 0)
       return tmp;
    return 0;
}
