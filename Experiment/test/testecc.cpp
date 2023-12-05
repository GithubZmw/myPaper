//void step2(Msg msg) {
//    //    ------------------------------ PAS_B生成Lics ------------------------------
//    BIG vskB;
//    randBig(&vskB);
//    BLS12383::ECP2 vpkB;
//    BLS12383::ECP2_copy(&vpkB, &params.g2);
//    BLS12383::ECP2_mul(&vpkB, vskB);
//
//    BLS12383::ECP Lics;
//    BIG temp;
//    BIG_copy(temp, msg.ID_A);
//    BIG_modadd(temp, temp, vskB, params.p_widetilde);
//    BIG_invmodp(temp, temp, params.p_widetilde);
//    BLS12383::ECP_copy(&Lics, &params.g1);
//    BLS12383::ECP_mul(&Lics, temp);
//    //    ------------------------------ PAS_A验证Lics ------------------------------
//    BLS12383::FP12 left, right;
//    left = e2(params.g1, params.g2);
//    BLS12383::ECP2 vpkBAddg2;
//    BLS12383::ECP2_copy(&vpkBAddg2, &params.g2);
//    BLS12383::ECP2_mul(&vpkBAddg2, msg.ID_A);
//    BLS12383::ECP2_add(&vpkBAddg2, &vpkB);
//    right = e2(Lics, vpkBAddg2);
//    bool flag = msg.flag;
//    flag = flag && (FP12_equals(&left, &right));
//    cout << "verify Lics:" << endl;
//    cout << "flag:" << flag << endl;


//    //    ------------------------------ 按需生成伪身份 ------------------------------
//    octet sk_p = {0, sizeof(s1), s1};
//    octet pk_p = {0, sizeof(w1), w1};
//    getKeyPair(&sk_p, &pk_p);
//
//    BIG pid;
//    randBig(&pid);
//    ECC_encAndDec();
//    inBlack(pid);//检查是否在黑名单
//    BIG sk1, sk2, sk3;
//    randBig(&sk1);
//    randBig(&sk2);
//    randBig(&sk3);
//    BLS12383::ECP pk1, pk2, pk3;
//    BLS12383::ECP_copy(&pk1, &params.g);
//    BLS12383::ECP_copy(&pk2, &params.g);
//    BLS12383::ECP_copy(&pk3, &params.g);
//    BLS12383::ECP_mul(&pk1, sk1);
//    BLS12383::ECP_mul(&pk2, sk2);
//    BLS12383::ECP_mul(&pk3, sk3);
////    为每个ski选择一个t-1阶的多项式

////  使用pki对ID_A进行加密得到(u,v,w)
//    BIG r;
//    randBig(&r);
//    BLS12383::ECP u, w, v;
//    // 求u
//    BLS12383::ECP_copy(&u, &params.g);
//    BLS12383::ECP_mul(&u, r);
//    // 求w
//    BLS12383::ECP_copy(&w, &pk1);
//    BLS12383::ECP_mul(&w, r);
//    BIG one;
//    BIG_one(one);
//    BIG_modadd(temp, one, params.n, params.p_widetilde);
//    mp mp = powmod(temp, msg.ID_A, params.p_widetilde);
//    BLS12383::ECP_mul(&w, mp.big);
//    // 求 v
//    BIG h_uw;
//    char str1[384], str2[384];
//    octet ecp_oc, ecp_oc1;
//    ecp_oc.val = str1;
//    ecp_oc.max = 97;
//    ecp_oc1.val = str2;
//    ecp_oc1.max = 97;
//    BLS12383::ECP_toOctet(&ecp_oc, &u, true);
//    BLS12383::ECP_toOctet(&ecp_oc1, &w, true);
//    OCT_xor(&ecp_oc, &ecp_oc1);
//    hashtoZp384_CCAP(h_uw, &ecp_oc, params.p_widetilde);
//    ECP_mul(&pk3, h_uw);
//    ECP_copy(&v, &pk2);
//    ECP_add(&v, &pk3);
//    BLS12383::ECP pk2_pk3_h;
//    ECP_copy(&pk2_pk3_h, &v);
//    BLS12383::ECP_mul(&v, r);
//
//
//    cout << endl << endl;
//    cout << "-----------u:" << endl;
//    ECP_output(&u);
//    cout << "-----------w:" << endl;
//    ECP_output(&w);
//    cout << "-----------v:" << endl;
//    ECP_output(&v);
//    cout << endl << endl;

//    生成零知识证
    BLS12383::ECP g11, g12, g13;
    randBig(&r);
    ECP_mul(&g11, r);
    randBig(&r);
    ECP_mul(&g12, r);
    randBig(&r);
    ECP_mul(&g13, r);
    // 生成随机数
    BIG gamma, epsilon, beta1, beta2, beta3, beta4;
    randBig(&gamma);
    randBig(&epsilon);
    randBig(&beta1);
    randBig(&beta2);
    randBig(&beta3);
    randBig(&beta4);
    //计算
    BIG d;
    BIG_one(d);
    for (auto it = BlackList.begin(); it != BlackList.end(); ++it) {
        BIG bigValue;
        BIG_copy(bigValue, it->second);
        BIG mod;
        BIG_modadd(mod, msg.ID_A, params.tau, params.p_widetilde);
        BIG d_pre;
        BIG_copy(d_pre, d);
        BIG_mod(d_pre, mod);
        BIG_modadd(d, bigValue, params.tau, mod);
        BIG_modmul(d, d_pre, d, mod);
        BIG_mod(d, params.p_widetilde);
    }
    BLS12383::ECP a;
    BIG mul;
    BIG_zero(mul);
    BIG mod;
    BIG_modadd(mod, msg.ID_A, params.tau, params.p_widetilde);
    for (auto it = BlackList.begin(); it != BlackList.end(); ++it) {
        BIG bigValue;
        BIG_copy(bigValue, it->second);
        BIG_modadd(d, bigValue, params.tau, mod);
        BIG_modmul(mul, mul, d, mod);
        BIG_mod(mul, params.p_widetilde);
    }
    BIG_sub(mul, mul, d);
    ECP_copy(&a, &params.g1);
    ECP_mul(&a, mul);
    BIG_invmodp(mod, mod, params.p_widetilde);
    ECP_mul(&a, mod);
    // 计算A
    BLS12383::ECP A;
    ECP_copy(&A, &params.g1);
    ECP_mul(&A, msg.ID_A);
    BLS12383::ECP h1;
    ECP_copy(&h1, &params.h1);
    ECP_mul(&h1, epsilon);
    ECP_add(&A, &h1);
    // 计算c
    BLS12383::ECP C;
    ECP_copy(&C, &Lics);
    ECP_mul(&C, gamma);
    // 计算 theta1,theta2,theta3,theta4,
    BIG theta1, theta2, theta3, theta4;
    BIG_mul(theta1, msg.ID_A, beta1);
    BIG_mul(theta2, msg.ID_A, beta2);
    BIG_mul(theta3, msg.ID_A, beta3);
    BIG_mul(theta4, msg.ID_A, beta4);
    // 计算 B1,B2,B3,B4
    BLS12383::ECP B1, B2, B3, B4;
    BLS12383::ECP g_1, h_1;
    ECP_copy(&h_1, &params.h1);
    ECP_copy(&B1, &params.g1);
    ECP_mul(&B1, beta1);
    ECP_mul(&h_1, beta2);
    ECP_add(&B1, &h_1);

    ECP_copy(&h_1, &params.h1);
    ECP_mul(&h_1, beta1);
    ECP_copy(&B2, &a);
    ECP_add(&B2, &h_1);

    ECP_copy(&g_1, &g11);
    ECP_copy(&h_1, &g12);
    ECP_mul(&g_1, beta3);
    ECP_mul(&h_1, beta4);
    ECP_copy(&B3, &h_1);
    ECP_add(&B3, &g_1);

    ECP_copy(&B4, &g13);
    ECP_mul(&B4, theta3);
    // 选择13个随机数
    BIG r_d, epsilon_d, sigma_d, gamma_d, d_d, theta1_d, theta2_d, theta3_d, theta4_d, beta1_d, beta2_d, beta3_d, beta4_d;
    randBig(&r_d);
    randBig(&epsilon_d);
    randBig(&sigma_d);
    randBig(&gamma_d);
    randBig(&d_d);
    randBig(&theta1_d);
    randBig(&theta2_d);
    randBig(&theta3_d);
    randBig(&theta4_d);
    randBig(&beta1_d);
    randBig(&beta2_d);
    randBig(&beta3_d);
    randBig(&beta4_d);
    // 计算 u_d, w_d, v_d;
    BLS12383::ECP u_d, w_d, v_d;
    BIG two;
    BIG_one(one);
    BIG_add(two, one, one);

    BIG r_d_2,sigma_d_2;
    BIG_modmul(r_d_2,r_d,two,params.p_widetilde);
    BIG_modmul(sigma_d_2,sigma_d,two,params.p_widetilde);

//    //求 u_d
//    BLS12383::ECP_copy(&u_d, &params.g);
//    BLS12383::ECP_mul(&u_d, r_d_2);
//    // 求 w_d
//    BIG_one(one);
//    BIG_modadd(one, one, params.n, params.p_widetilde);
//    mp = powmod(one, sigma_d_2, params.p_widetilde);
//    BLS12383::ECP_mul(&w_d, mp.big);
//    // 求 v_d
//    ECP_copy(&v_d, &pk2_pk3_h);
//    BLS12383::ECP_mul(&v_d, r_d_2);

    // 计算A_d,C_d
    BLS12383::ECP A_d;
//    FP12 C_d;
//    ECP_copy(&g_1, &params.g1);
//    ECP_copy(&h_1, &params.h1);
//    ECP_mul(&g_1, sigma_d);
//    ECP_mul(&h_1, epsilon_d);
//    ECP_add(&g_1, &h_1);
//    ECP_copy(&A_d, &g_1);
//
//    FP12 fp1, fp2;
//    fp1 = e2(C, params.g2);
//    FP12_pow(&fp1, &fp1, sigma_d);
//    FP12_reduce(&fp1);
//    FP12_inv(&fp1, &fp1);
//    FP12_reduce(&fp1);
//    fp2 = e2(params.g1, params.g2);
//    FP12_pow(&fp2, &fp2, gamma_d);
//    FP12_reduce(&fp2);
//    FP12_copy(&C_d, &fp1);
//    FP12_mul(&C_d, &fp2);
//    FP12_reduce(&C_d);
//    // 计算 B11_d,B12_d,B31_d,B32_d,B4_d
//    BLS12383::ECP B11_d, B12_d, B31_d, B32_d, B4_d;
//    ECP_copy(&g_1, &params.g1);
//    ECP_copy(&h_1, &params.h1);
//    ECP_mul(&g_1, beta1_d);
//    ECP_mul(&h_1, beta2_d);
//    ECP_add(&g_1, &h_1);
//    ECP_copy(&B11_d, &g_1);
//
//    ECP_copy(&h_1, &params.h1);
//    ECP_copy(&g_1, &params.g1);
//    ECP_mul(&g_1, theta1_d);
//    BLS12383::ECP ecp;
//    ECP_copy(&h_1, &h_1);
//    ECP_mul(&h_1, theta2_d);
//    ECP_copy(&ecp, &B1);
//    BIG_invmodp(sigma_d, sigma_d, params.p_widetilde);
//    ECP_mul(&ecp, sigma_d);
//    ECP_add(&ecp, &g_1);
//    ECP_add(&ecp, &h_1);
//    ECP_add(&B12_d, &ecp);
//
//    ECP_copy(&g_1, &g11);
//    ECP_copy(&h_1, &g12);
//    ECP_mul(&g_1, beta3_d);
//    ECP_mul(&h_1, beta4_d);
//    ECP_copy(&B31_d, &g_1);
//    ECP_add(&B31_d, &h_1);
//
//    ECP_copy(&g_1, &g11);
//    ECP_copy(&h_1, &g12);
//    ECP_copy(&ecp, &B3);
//    ECP_mul(&g_1, theta3_d);
//    ECP_mul(&h_1, theta4_d);
//    BIG_invmodp(d_d, d_d, params.p_widetilde);
//    ECP_mul(&ecp, d_d);
//    ECP_copy(&B31_d, &g_1);
//    ECP_add(&B31_d, &h_1);
//    ECP_add(&B31_d, &ecp);
//
//    ECP_copy(&h_1, &g11);
//    ECP_copy(&g_1, &g12);
//    ECP_mul(&g_1, theta3_d);
//    ECP_mul(&h_1, theta4_d);
//    ECP_copy(&ecp, &B3);
//    BIG_invmodp(sigma_d, sigma_d, params.p_widetilde);
//    ECP_mul(&ecp, sigma_d);
//    ECP_add(&ecp, &g_1);
//    ECP_add(&ecp, &h_1);
//    ECP_add(&B32_d, &ecp);
//
//    ECP_copy(&g_1, &g13);
//    ECP_mul(&g_1, theta3_d);
//    ECP_copy(&B4, &g_1);

    // 计算D_d
    FP12 D_d;
    fp1 = e2(params.g1, params.g2);
    FP12_pow(&fp1, &fp1, d_d);
    FP12_reduce(&fp1);
    FP12_inv(&fp1, &fp1);
    FP12_reduce(&fp1);
    fp2 = e2(params.h1, params.g2);
    FP12_pow(&fp2, &fp2, theta1_d);
    FP12_reduce(&fp2);
    FP12_mul(&fp1, &fp2);
    FP12_reduce(&fp1);
    fp2 = e2(params.h1, params.g2);
    FP12_pow(&fp2, &fp2, beta1_d);
    FP12_reduce(&fp2);
    FP12_pow(&fp2, &fp2, params.tau);
    FP12_reduce(&fp2);
    FP12_mul(&fp1, &fp2);
    FP12_reduce(&fp1);
    fp2 = e2(B2, params.g2);
    FP12_pow(&fp2, &fp2, sigma_d);
    FP12_inv(&fp2, &fp2);
    FP12_reduce(&fp2);
    FP12_mul(&fp1, &fp2);
    FP12_reduce(&fp1);
    FP12_copy(&D_d, &fp1);


    // 计算挑战ch
    BIG ch;
    octet oc1_ch, oc2_ch;
    oc1_ch.val = str1;
    oc1_ch.max = 97;
    oc2_ch.val = str2;
    oc2_ch.max = 97;
    // 将哈希函数中的变量全部转化为字符进行异或
    ECP_toOctet(&oc1_ch, &params.g1, true);
    ECP2_toOctet(&oc2_ch, &params.g2, true);
    OCT_xor(&oc1_ch, &oc2_ch);
    ECP_toOctet(&oc2_ch, &A, true);
    OCT_xor(&oc1_ch, &oc2_ch);
    ECP_toOctet(&oc2_ch, &A_d, true);
    OCT_xor(&oc1_ch, &oc2_ch);
    hashtoZp384_CCAP(ch, &oc1_ch, params.p_widetilde);

    // 计算 r_dd,epsilon_dd,sigma_dd,gamma_dd,d_dd,theta1_dd,theta2_dd,theta3_dd,theta4_dd,beta1_dd,beta2_dd,beta3_dd,beta4_dd;
    BIG r_dd, epsilon_dd, sigma_dd, gamma_dd, d_dd, theta1_dd, theta2_dd, theta3_dd, theta4_dd, beta1_dd, beta2_dd, beta3_dd, beta4_dd;;
    BIG_modmul(temp, ch, r, params.p_widetilde);
    BIG_modneg(temp,temp,params.p_widetilde);
    BIG_copy(r_dd, r_d);
    BIG_modadd(r_dd, r_dd, temp,params.p_widetilde);
    BIG_mod(r_dd, params.p_widetilde);





    BLS12383::ECP tttt1,tttt2,tttt3;
    BLS12383::ECP_copy(&tttt1,&params.g);
    ECP_mul(&tttt1,r_d_2);
    BLS12383::ECP_copy(&tttt2,&params.g);
    ECP_mul(&tttt2,r_dd_2);
    BLS12383::ECP_copy(&tttt3,&params.g);
    BIG_modneg(temp,temp,params.p_widetilde);
    BIG_modmul(temp,temp,two,params.p_widetilde);
    ECP_mul(&tttt3,temp);
    ECP_add(&tttt2,&tttt3);
    cout << ECP_equals(&tttt1,&tttt2) << endl;


//    // 检查 "u_d"
//    ECP_copy(&g_1,&u);
//    ECP_mul(&g_1,ch);
//    ECP_output(&g_1);


    ECP_copy(&h_1,&params.g);
    ECP_mul(&h_1,r_dd_2);
    ECP_add(&g_1,&h_1);
    cout << "check u_d :: result = " << ECP_equals(&u_d,&g_1) << endl;// ----------------------------------------------


    BIG_one(one);
    cout << "ch*r" << endl;
    BIG_output(temp);
    cout << endl;
    cout << "r_d" << endl;
    BIG_output(r_d);
    cout << endl;

    BIG_modmul(temp, ch, epsilon, params.p_widetilde);
    BIG_modneg(temp,temp,params.p_widetilde);
    BIG_copy(epsilon_dd, epsilon_d);
    BIG_modadd(epsilon_dd, epsilon_dd, temp,params.p_widetilde);
    BIG_mod(epsilon_dd, params.p_widetilde);

    BIG_modmul(temp, ch, msg.ID_A, params.p_widetilde);
    BIG_modneg(temp,temp,params.p_widetilde);
    BIG_copy(sigma_dd, sigma_d);
    BIG_modadd(sigma_dd, sigma_dd, temp,params.p_widetilde);
    BIG_mod(sigma_dd, params.p_widetilde);

    BIG_modmul(temp, ch, gamma, params.p_widetilde);
    BIG_modneg(temp,temp,params.p_widetilde);
    BIG_copy(gamma_dd, gamma_d);
    BIG_modadd(gamma_dd, gamma_dd, temp,params.p_widetilde);
    BIG_mod(gamma_dd, params.p_widetilde);


    BIG_modmul(temp, ch, d, params.p_widetilde);
    BIG_modneg(temp,temp,params.p_widetilde);
    BIG_copy(d_dd, d_d);
    BIG_modadd(d_dd, d_dd, temp,params.p_widetilde);
    BIG_mod(d_dd, params.p_widetilde);

    BIG_modmul(temp, ch, beta1, params.p_widetilde);
    BIG_modneg(temp,temp,params.p_widetilde);
    BIG_copy(beta1_dd, beta1_d);
    BIG_modadd(beta1_dd, beta1_dd, temp,params.p_widetilde);
    BIG_mod(beta1_dd, params.p_widetilde);

    BIG_modmul(temp, ch, beta2, params.p_widetilde);
    BIG_modneg(temp,temp,params.p_widetilde);
    BIG_copy(beta2_dd, beta2_d);
    BIG_modadd(beta2_dd, beta2_dd, temp,params.p_widetilde);
    BIG_mod(beta2_dd, params.p_widetilde);

    BIG_modmul(temp, ch, beta3, params.p_widetilde);
    BIG_modneg(temp,temp,params.p_widetilde);
    BIG_copy(beta3_dd, beta3_d);
    BIG_modadd(beta3_dd, beta3_dd, temp,params.p_widetilde);
    BIG_mod(beta3_dd, params.p_widetilde);

    BIG_modmul(temp, ch, beta4, params.p_widetilde);
    BIG_modneg(temp,temp,params.p_widetilde);
    BIG_copy(beta4_dd, beta4_d);
    BIG_modadd(beta4_dd, beta4_dd, temp,params.p_widetilde);
    BIG_mod(beta4_dd, params.p_widetilde);

    BIG_modmul(temp, ch, theta1, params.p_widetilde);
    BIG_modneg(temp,temp,params.p_widetilde);
    BIG_copy(theta1_dd, theta1_d);
    BIG_modadd(theta1_dd, theta1_dd, temp,params.p_widetilde);
    BIG_mod(theta1_dd, params.p_widetilde);

    BIG_modmul(temp, ch, theta2, params.p_widetilde);
    BIG_modneg(temp,temp,params.p_widetilde);
    BIG_copy(theta2_dd, theta2_d);
    BIG_modadd(theta2_dd, theta2_dd, temp,params.p_widetilde);
    BIG_mod(theta2_dd, params.p_widetilde);

    BIG_modmul(temp, ch, theta3, params.p_widetilde);
    BIG_modneg(temp,temp,params.p_widetilde);
    BIG_copy(theta3_dd, theta3_d);
    BIG_modadd(theta3_dd, theta3_dd, temp,params.p_widetilde);
    BIG_mod(theta3_dd, params.p_widetilde);

    BIG_modmul(temp, ch, theta4, params.p_widetilde);
    BIG_modneg(temp,temp,params.p_widetilde);
    BIG_copy(theta4_dd, theta4_d);
    BIG_modadd(theta4_dd, theta4_dd, temp,params.p_widetilde);
    BIG_mod(theta4_dd, params.p_widetilde);

//    签名验证
    BLS12383::ECP blk;
    BIG_one(mul);
    for (auto it = BlackList.begin(); it != BlackList.end(); ++it) {
        BIG bigValue;
        BIG_copy(bigValue, it->second);
        BIG_modadd(bigValue, bigValue, params.tau, mod);
        BIG_modmul(mul, mul, bigValue, params.p_widetilde);
    }
    ECP_mul(&blk, mul);

    // 计算挑战c_hat
    BIG ch_hat;
    oc1_ch.val = str1;
    oc1_ch.max = 97;
    oc2_ch.val = str2;
    oc2_ch.max = 97;
    // 将哈希函数中的变量全部转化为字符进行异或
    ECP_toOctet(&oc1_ch, &params.g1, true);
    ECP2_toOctet(&oc2_ch, &params.g2, true);
    OCT_xor(&oc1_ch, &oc2_ch);
    ECP_toOctet(&oc2_ch, &A, true);
    OCT_xor(&oc1_ch, &oc2_ch);
    ECP_toOctet(&oc2_ch, &A_d, true);
    OCT_xor(&oc1_ch, &oc2_ch);
    hashtoZp384_CCAP(ch_hat, &oc1_ch, params.p_widetilde);
    cout << "ch_hat ?= ch  :: ==>>  " << (BIG_comp(ch, ch_hat) == 0 ? "true" : "false" )<< endl;

//    BIG ch_2;
//    BIG_copy(ch_2,ch_hat);
//    BIG_modmul(ch_2,ch_2,two,params.p_widetilde);
//
//
//    BIG r_dd_2;
//    BIG_copy(r_dd_2,r_dd);
//    BIG_modmul(r_dd_2,r_dd_2,two,params.p_widetilde);

    BIG sigma_dd_2;
    BIG_copy(sigma_dd_2,sigma_dd);
    BIG_modmul(sigma_dd_2,sigma_dd_2,two,params.p_widetilde);



//    // 检查 "u_d"
//    ECP_copy(&g_1,&u);
//    ECP_copy(&h_1,&params.g);
//    ECP_mul(&g_1,ch_2);
//    ECP_mul(&h_1,r_dd_2);
//    ECP_add(&g_1,&h_1);
//    cout << "check u_d :: result = " << ECP_equals(&u_d,&g_1) << endl;// ----------------------------------------------
//     检查"w_d"
//    ECP_copy(&g_1,&w);
//    ECP_copy(&h_1,&pk1);
//    ECP_mul(&g_1,ch_2);
//    BIG_modadd(one,one,params.n,params.p_widetilde);
//    mp = powmod(one,sigma_dd_2,params.p_widetilde);
//    ECP_mul(&h_1,mp.big);
//    ECP_add(&g_1,&h_1);
//    ECP_copy(&ecp,&g_1);
//    cout << "check w_d :: result = " << ECP_equals(&w_d,&ecp) << endl;// ----------------------------------------------
//    // 检查 "v_d"
//    ECP_copy(&g_1,&v);
//    ECP_copy(&h_1,&pk2_pk3_h);
//    ECP_mul(&g_1,ch_2);
//    ECP_mul(&h_1,r_dd_2);
//    ECP_add(&g_1,&h_1);
//    ECP_copy(&ecp,&g_1);
//    cout << "check v_d :: result = " << ECP_equals(&v_d,&ecp) << endl;// ---------------------这里比较绝对值-------------------------

//
//    ECP_copy(&g_1,&params.g1);
//    ECP_copy(&h_1,&params.h1);
//    ECP_copy(&ecp,&A);
//    ECP_mul(&g_1,sigma_dd);
//    ECP_mul(&h_1,epsilon_dd);
//    ECP_mul(&ecp,ch_hat);
//    ECP_add(&g_1,&h_1);
//    ECP_add(&ecp,&g_1);
//    ECP_add(&ecp,&g_1);
//    ECP_equals(&A_d,&ecp);// ----------------------------------------------
//
//    fp1 = e2(C,vpkB);
//    FP12_pow(&fp1,&fp1,ch_hat);
//    FP12_reduce(&fp1);
//    fp2 = e2(C,params.g2);
//    FP12_pow(&fp2,&fp2,sigma_dd);
//    FP12_reduce(&fp2);
//    FP12_inv(&fp2,&fp2);
//    FP12_reduce(&fp2);
//    FP12 fp3,fp12;
//    fp3 = e2(params.g1,params.g2);
//    FP12_pow(&fp3,&fp3,gamma_dd);
//    FP12_reduce(&fp3);
//    FP12_copy(&fp12,&fp1);
//    FP12_mul(&fp12,&fp2);
//    FP12_reduce(&fp12);
//    FP12_mul(&fp12,&fp3);
//    FP12_reduce(&fp12);
//    FP12_equals(&C_d,&fp12);// ----------------------------------------------
//
//    // 验证 B
//    ECP_copy(&g_1,&params.g1);
//    ECP_copy(&h_1,&params.h1);
//    ECP_copy(&ecp,&B1);
//    ECP_mul(&g_1,beta1_dd);
//    ECP_mul(&h_1,beta2_dd);
//    ECP_mul(&ecp,ch_2);
//    ECP_add(&g_1,&h_1);
//    ECP_add(&ecp,&g_1);
//    ECP_equals(&B11_d,&ecp);// ----------------------------------------------
//
//    // 验证 B
//    ECP_copy(&g_1,&params.g1);
//    ECP_copy(&h_1,&params.h1);
//    ECP_copy(&ecp,&B1);
//    ECP_mul(&g_1,theta1_dd);
//    ECP_mul(&h_1,theta2_dd);
//    BIG sigma_dd_inv;
//    BIG_copy(sigma_dd_inv,sigma_dd);
//    BIG_invmodp(sigma_dd_inv,sigma_dd_inv,params.p_widetilde);
//    ECP_mul(&ecp,sigma_dd_inv);
//    ECP_add(&g_1,&h_1);
//    ECP_add(&ecp,&g_1);
//    ECP_equals(&B12_d,&ecp);// ----------------------------------------------
//
//
//    // 验证 B
//    ECP_copy(&g_1,&g11);
//    ECP_copy(&h_1,&g12);
//    ECP_copy(&ecp,&B3);
//    ECP_mul(&g_1,beta3_dd);
//    ECP_mul(&h_1,beta4_dd);
//    ECP_mul(&ecp,ch_hat);
//    ECP_add(&g_1,&h_1);
//    ECP_add(&ecp,&g_1);
//    ECP_equals(&B31_d,&ecp);// ----------------------------------------------
//
//    // 验证 B
//    BIG d_dd_inv;
//    BIG_copy(d_dd_inv,d_dd);
//    BIG_invmodp(d_dd_inv,d_dd_inv,params.p_widetilde);
//    ECP_copy(&g_1,&g11);
//    ECP_copy(&h_1,&g12);
//    ECP_copy(&ecp,&B3);
//    ECP_mul(&g_1,theta3_dd);
//    ECP_mul(&h_1,theta4_dd);
//    ECP_mul(&ecp,d_dd_inv);
//    ECP_add(&g_1,&h_1);
//    ECP_add(&ecp,&g_1);
//    ECP_equals(&B32_d,&ecp);// ----------------------------------------------
//
//    // 验证 B4
//    ECP_copy(&g_1,&g13);
//    ECP_copy(&ecp,&B4);
//    ECP_mul(&g_1,theta3_dd);
//    ECP_mul(&ecp,ch_hat);
//    ECP_add(&ecp,&g_1);
//    ECP_equals(&B4,&ecp);// ----------------------------------------------
//
    // 验证D
//    fp1 = e2(B2,params.g2);
//    FP12_pow(&fp1,&fp1,params.tau);
//    FP12_reduce(&fp1);
//    fp2 = e2(blk,params.g2);
//    FP12_inv(&fp2,&fp2);
//    FP12_reduce(&fp2);
//    FP12_mul(&fp1,&fp2);
//    FP12_reduce(&fp1);
//    FP12_pow(&fp1,&fp1,ch_hat);
//    FP12_reduce(&fp1);
//    fp3 = e2(params.g1,params.g2);
//    FP12_pow(&fp3,&fp3,d_dd);
//    FP12_reduce(&fp3);
//    FP12_inv(&fp3,&fp3);
//    FP12_reduce(&fp3);
//    FP12_mul(&fp1,&fp3);
//    FP12_reduce(&fp1);
//
//    fp3 = e2(params.h1,params.g2);
//    FP12_pow(&fp3,&fp3,theta1_dd);
//    FP12_reduce(&fp3);
//    FP12_mul(&fp1,&fp3);
//    FP12_reduce(&fp1);
//
//    fp3 = e2(params.h1,params.g2);
//    FP12_pow(&fp3,&fp3,beta1_dd);
//    FP12_reduce(&fp3);
//    FP12_pow(&fp3,&fp3,params.tau);
//    FP12_reduce(&fp3);
//    FP12_mul(&fp1,&fp3);
//    FP12_reduce(&fp1);
//
//    fp3 = e2(B2,params.g2);
//    FP12_pow(&fp3,&fp3,sigma_dd);
//    FP12_reduce(&fp3);
//    FP12_inv(&fp3,&fp3);
//    FP12_reduce(&fp3);
//    FP12_mul(&fp1,&fp3);
//    FP12_reduce(&fp1);
//    FP12_equals(&D_d,&fp12);// ----------------------------------------------
}



