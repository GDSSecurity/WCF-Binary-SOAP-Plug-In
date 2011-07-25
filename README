WCF Binary Soap Plug-In
Created by Brian Holyfield (labs@gdssecurity.com)
Copyright (c) 2009 Gotham Digital Science - All Rights Reserved

This software is released under the Reciprocal Public License 1.5 (RPL1.5)http://www.opensource.org/licenses/rpl1.5

There are two different versions of the plug-in:
burp_wcf_plugin - Burp Free Edition plug-in 
burp_pro_wcf_plugin - Burp Professional Edition plug-in

The WCF Binary Soap Plug-In is designed to encode and decode WCF Binary Soap data ("Content-Type: application/soap+msbin1”).  The Burp Professional Edition plug-in is capable of editing request data ONLY. Please use the Free Edition plug-in if you would like to edit response data.

Due to a limitation of the Burp Free Edition Extender interface at the time of writing, editing request and response data requires two Burp instances to be chained together:

- The first instance handles decoding requests, intercepting (and editing) 
  requests, and re-encoding edited responses.

- The second instance handles re-encoding edited requests, decoding 
  responses, and intercepting (and editing) responses.  

For more information, consult http://www.gdssecurity.com/l/b/

NOTE: Make sure that NBFS.exe is in the same directory as BurpExtender.jar

Usage:  java -Xmx512m -classpath BurpExtender.jar;path_to_burp.jar burp.StartBurp 

