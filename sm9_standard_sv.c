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


int SM9_standard_sign(unsigned char hid[], unsigned char* IDA, unsigned char* message,
    int len, unsigned char rand[], unsigned char dsa[],
    unsigned char Ppub[], unsigned char H[], unsigned char S[])
{
    big r, h, l, xdSA, ydSA;
    big xS, yS, tmp, zero;
    zzn12 g, w;
    epoint* s, *dSA;
    ecn2 Ppubs;
    int Zlen, buf;
    unsigned char* Z = NULL;
    
    //initiate
    r = mirvar(0);
    h = mirvar(0);
    l = mirvar(0);
    tmp = mirvar(0);
    zero = mirvar(0);
    xS = mirvar(0);
    yS = mirvar(0);
    xdSA = mirvar(0);
    ydSA = mirvar(0);
    s = epoint_init();
    dSA = epoint_init();
    Ppubs.x.a = mirvar(0);
    Ppubs.x.b = mirvar(0);
    Ppubs.y.a = mirvar(0);
    Ppubs.y.b = mirvar(0);
    Ppubs.z.a = mirvar(0);
    Ppubs.z.b = mirvar(0);
    Ppubs.marker = MR_EPOINT_INFINITY;
    zzn12_init(&g);
    zzn12_init(&w);

    bytes_to_big(BNLEN, rand, r);
    bytes_to_big(BNLEN, dsa, xdSA);
    bytes_to_big(BNLEN, dsa + BNLEN, ydSA);
    epoint_set(xdSA, ydSA, 0, dSA);
    bytes128_to_ecn2(Ppub,&Ppubs);

    //A1 g=e(P1,Ppubs-s)
    if (!ecap(Ppubs, P1, para_t, X, &g))
        return SM9_MY_ECAP_12A_ERR;
    if (!member(g, para_t, X))
        return SM9_MEMBER_ERR;

    printf("\n***********************g=e(P1,Ppubs):****************************\n");
    zzn12_ElementPrint(g);

    //A2: w=g(r)
    printf("\n***********************randnum r:********************************\n");
    cotnum(r, stdout);
    w = zzn12_pow(g, r);
    printf("\n***************************w=gr:**********************************\n");
    zzn12_ElementPrint(w);

    //Step3:calculate h=H2(M||w,N)
    Zlen = len + 32 * 12; //这里是什么
    Z = (char*)malloc(sizeof(char) * (Zlen + 1));
    if(Z==NULL)
        return SM9_ASK_MEMORY_ERR;

    LinkCharZzn12(message, len, w, Z, Zlen);
    buf = SM9_standard_h2(Z, Zlen, N, h);
    if (buf != 0)
        return buf;
    printf("\n****************************h:*************************************\n");
    cotnum(h, stdout);

    //Step4:l=(r-h)mod N
    subtract(r, h, l);
    divide(l, N, tmp);
    while (mr_compare(l, zero) < 0)
        add(l, N, l);
    if (mr_compare(l, zero) == 0)
        return SM9_L_error;
    printf("\n**************************l=(r-h)mod N:****************************\n");
    cotnum(l, stdout);

    //Step5:S=[l]dSA=(xS,yS)
    ecurve_mult(l, dSA, s);
    epoint_get(s, xS, yS);
    printf("\n**************************S=[l]dSA=(xS,yS):*************************\n");
    cotnum(xS, stdout);
    cotnum(yS, stdout);

    big_to_bytes(32, h, H, 1);
    big_to_bytes(32, xS, S, 1);
    big_to_bytes(32, yS, S + 32, 1);

    free(Z);
    return 0;
}