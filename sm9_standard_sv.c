#include "sm9_standard.h"
#include "miracl.h"
#include "mirdef.h"
#include <math.h>

/*密码函数H2*/
int SM9_standard_h2(unsigned char Z[], int Zlen, big n, big h2)
{
    /*
    输入: unsigned char Z 比特串Z
    输入: big n 整数n
    输出: big h2 整数在[1,n-1]
    */
    int hlen, ZHlen, i;
    big hh, i256, tmp, n1;
    unsigned char *ZH = NULL, *ha = NULL;

    hh = mirvar(0);
    i256 = mirvar(0);
    tmp = mirvar(0);
    n1 = mirvar(0);
    convert(1, i256);
    ZHlen = Zlen + 1;

    hlen = (int)ceil((5.0 * logb2(n)) / 32.0); //向上舍入为最接近的整数
    decr(n, 1, n1); //整数h2在[1,n-1]范围内
    ZH = (char *)malloc(sizeof(char)*(ZHlen + 1));
    if(ZH == NULL) 
        return SM9_ASK_MEMORY_ERR;
    memcpy(ZH + 1, Z, Zlen);
    ZH[0] = 0x02;
    ha = (char *)malloc(sizeof(char)*(hlen + 1));
    if(ha == NULL) 
        return SM9_ASK_MEMORY_ERR;
    SM3_kdf(ZH, ZHlen, hlen, ha); //

    for(i = hlen - 1; i >= 0; i--)//key[从大到小]
    {
        premult(i256, ha[i], tmp);
        add(hh, tmp, hh);
        premult(i256, 256, i256);
        divide(i256, n1, tmp);
        divide(hh, n1, tmp);
    }
    incr(hh, 1, h2);
    free(ZH);
    free(ha);
    return 0;
}



int SM9_standard_generatesignkey(unsigned char hid[], unsigned char *ID, int IDlen, big ks, unsigned char Ppubs[], unsigned char dsa[])
{
    big h1, t1, t2, rem, xdSA, ydSA, tmp;
    unsigned char* Z = NULL;
    int Zlen = IDlen + 1, buf;
    ecn2 Ppub;
    epoint* dSA;

    h1 = mirvar(0);
    t1 = mirvar(0);
    t2 = mirvar(0);
    rem = mirvar(0);
    tmp = mirvar(0);
    xdSA = mirvar(0);
    ydSA = mirvar(0);
    dSA = epoint_init();
    Ppub.x.a = mirvar(0);
    Ppub.x.b = mirvar(0);
    Ppub.y.a = mirvar(0);
    Ppub.y.b = mirvar(0);
    Ppub.z.a = mirvar(0);
    Ppub.z.b = mirvar(0);
    Ppub.marker = MR_EPOINT_INFINITY;

    Z = (char*)malloc(sizeof(char) * (Zlen + 1));
    memcpy(Z, ID, IDlen);
    memcpy(Z + IDlen, hid, 1);
    //t1=H1(IDA||hid,N)
    buf = SM9_standard_h1(Z, Zlen, N, h1);
    if (buf != 0)
        return buf;
    add(h1, ks, t1);
    xgcd(t1, N, t1, t1, t1); //t1=t1(-1)
    multiply(ks, t1, t2);
    divide(t2, N, rem); //t2=ks*t1(-1)

    //dSA=[t2]P1
    ecurve_mult(t2, P1, dSA);

    //Ppub=[ks]P2
    ecn2_copy(&P2, &Ppub);
    ecn2_mul(ks, &Ppub);

    printf("\n****************The signed key = (xdA,ydA):***************\n");
    epoint_get(dSA, xdSA, ydSA);
    cotnum(xdSA, stdout);
    cotnum(ydSA, stdout);
    printf("\n****************PublicKey Ppubs=[ks]P2:*******************\n");
    ecn2_Bytes128_Print(Ppub);

    epoint_get(dSA, xdSA, ydSA);
    big_to_bytes(BNLEN, xdSA, dsa, 1);
    big_to_bytes(BNLEN, ydSA, dsa + BNLEN, 1);

    redc(Ppub.x.b, tmp);
    big_to_bytes(BNLEN, tmp, Ppubs, 1);
    redc(Ppub.x.a, tmp);
    big_to_bytes(BNLEN, tmp, Ppubs + BNLEN, 1);
    redc(Ppub.y.b, tmp);
    big_to_bytes(BNLEN, tmp, Ppubs + BNLEN * 2, 1);
    redc(Ppub.y.a, tmp);
    big_to_bytes(BNLEN, tmp, Ppubs + BNLEN * 3, 1);

    free(Z);
    return 0;
}


