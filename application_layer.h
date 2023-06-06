/**
 * Neither of 'application_layer.h' and 'application_layer.cpp' 
 * contains the implementation of app-layer protocol parsing.
 * 
 * Only provide parsing interfaces for app-layer protocols.
*/

#ifndef _APPLICATION_LAYER_H_
#define _APPLICATION_LAYER_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>

#include "base_type.h"
#include "app_layer_protos/dns.h"

using std::vector;
using std::string;

void print_dns_info(char8_t* dns_pkt);

#endif
