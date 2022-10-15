#ifndef _COMMON_H
#define _COMMON_H

#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

#include <QString>
#include "crypto.h"

#define STAGE_ERROR     -1  /* Error detected                   */
#define STAGE_INIT       0  /* Initial stage                    */
#define STAGE_HANDSHAKE  1  /* Handshake with client            */
#define STAGE_RESOLVE    4  /* Resolve the hostname             */
#define STAGE_STREAM     5  /* Stream between client and server */
#define STAGE_STOP       6  /* Server stop to response          */

typedef struct ScSetting {
    int local_port;
    int remote_port;
    QString password;
    QString method;
    QString remote_host;
} ScSetting;

#endif // _COMMON_H
