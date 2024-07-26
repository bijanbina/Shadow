#ifndef SC_BACKEND_H
#define SC_BACKEND_H

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

typedef struct ScSetting
{
    int is_server;
    int local_port;
    int remote_port;
    QString password;
    QString remote_host;
} ScSetting;

#endif // SC_BACKEND_H
