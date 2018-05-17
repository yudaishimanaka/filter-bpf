//
// Created by yudai on 18/05/17.
//

#ifndef FILTER_BPF_FILTER_COMP_H
#define FILTER_BPF_FILTER_COMP_H

void filter_try_compile(const char *str, struct sock_fprog *cbpf, int link_type);

#endif //FILTER_BPF_FILTER_COMP_H
