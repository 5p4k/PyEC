"""
logging - trivial logging function

Only provides one function that formats the message accordingly to the logging type.
"""

LOG_INFO=1
LOG_WARNING=2
LOG_ERROR=4
LOG_INCOMING=8
LOG_IMPORTANTINFO=16

LOG_LEVEL=LOG_INFO | LOG_WARNING | LOG_ERROR | LOG_INCOMING | LOG_IMPORTANTINFO

def log(type, msgOrCaller, msgOrNone=None):
    """
    Outputs
        xxx [caller:] message
    if type matches the value of LOG_LEVEL.

    Input:
        type        Integer (LOG_INFO, LOG_WARNING, LOG_ERROR, LOG_INCOMING)
        msgOrCaller If msgOrNone is specified, it's the caller. Otherwise the message.
        msgOrNone   Optional. The message if specified.

    Remarks:
        xxx values according to type value:
            LOG_INFO        "..."
            LOG_WARNING     "???"
            LOG_ERROR       "!!!"
            LOG_INCOMING    "<<<"
    """
    if LOG_LEVEL & type == 0: return

    output="   "
    if type==LOG_INFO or type==LOG_IMPORTANTINFO:
        output="..."
    elif type==LOG_WARNING:
        output="???"
    elif type==LOG_ERROR:
        output="!!!"
    elif type==LOG_INCOMING:
        output="<<<"

    if msgOrNone==None:
        caller=None
        msg=msgOrCaller
    else:
        msg=msgOrNone
        caller=msgOrCaller

    if caller!=None:
        output+=" "+caller+":"

    output+=" "+msg
    print(output)