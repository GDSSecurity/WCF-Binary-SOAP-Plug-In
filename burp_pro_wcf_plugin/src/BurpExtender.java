// WCF Binary Soap Plug-In for Burp Professional
// Created by Brian Holyfield (labs@gdssecurity.com)
// Copyright (c) 2009 Gotham Digital Science - All Rights Reserved

import java.net.URL;
import java.util.*;
import java.util.regex.*;
import java.io.*;
import sun.misc.*;
import burp.*;

public class BurpExtender
{
    public void processHttpMessage(
            String toolName, 
            boolean messageIsRequest, 
            IHttpRequestResponse messageInfo) throws Exception
    {
        try 
        {
            byte[] message;
            if (messageIsRequest)
            {
                byte[] request = messageInfo.getRequest();
                messageInfo.setRequest(processWCFMessage(request));       
            }
            else 
            {
                // DO NOTHING FOR NOW
            }
        }
        catch (Exception e)
        {
            // HANDLE EXCEPTION
            messageInfo.setRequest(e.getMessage().getBytes());
        }
  	}

    public byte[] processProxyMessage(
            int messageReference,
            boolean messageIsRequest,
            String remoteHost,
            int remotePort,
            boolean serviceIsHttps,
            String httpMethod,
            String url,
            String resourceType,
            String statusCode,
            String responseContentType,
            byte[] message,
            int[] interceptAction)
    {
       try 
       {
            if (!messageIsRequest)
            {
                // SKIPPING RESPONSE 
                return message;
            }
            else 
            {
                return processWCFMessage(message);
            }
   	    }
        catch (Exception e)
        {
            return e.getMessage().getBytes();
  	    }
	}    
	
    private byte[] processWCFMessage(byte[] message) throws Exception
	{	
	        String strMessage = new String(message);
	        String[] strHeadersAndContent = strMessage.split("\\r\\n\\r\\n");
            if (strHeadersAndContent.length > 1)
            {
	            byte[] byteOrigMessageContent = strHeadersAndContent[1].getBytes();
                if (strHeadersAndContent[0].indexOf("Content-Type: application/soap+msbin1") > 1)
	            {
	                byte[] arrContent;
	                if (strHeadersAndContent[0].indexOf("X-WCF-Proxy: must-encode") > 1)
	                {
	                    strHeadersAndContent[0] = removeHttpHeader(strHeadersAndContent[0],"X-WCF-Proxy: must-encode\r\n");
    	                strHeadersAndContent[0] = strHeadersAndContent[0] + "\r\n\r\n";
		                String strBase64Decoded = new sun.misc.BASE64Encoder().encode(strHeadersAndContent[1].getBytes());
		                String strReturnBase64Encoded = encodeDecodeWcf("ENCODE", strBase64Decoded);
		                arrContent = new sun.misc.BASE64Decoder().decodeBuffer(strReturnBase64Encoded);
		            } else {    
        		        strHeadersAndContent[0] = strHeadersAndContent[0] + "\r\nX-WCF-Proxy: must-encode\r\n\r\n";
        		        String strBase64Encoded = new sun.misc.BASE64Encoder().encode(strHeadersAndContent[1].getBytes());
		                String strReturnBase64Decoded = encodeDecodeWcf("DECODE", strBase64Encoded);
		                arrContent = new sun.misc.BASE64Decoder().decodeBuffer(strReturnBase64Decoded);
		            }  
		            
		            strHeadersAndContent[0] = updateContentLength(strHeadersAndContent[0],arrContent.length);
		            byte[] arrHeaders = strHeadersAndContent[0].getBytes();
		            byte[] arrMessage = new byte[arrHeaders.length + arrContent.length];
		            System.arraycopy(arrHeaders, 0, arrMessage, 0, arrHeaders.length);
        	        System.arraycopy(arrContent, 0, arrMessage, arrHeaders.length, arrContent.length);
		            return arrMessage;
	            }
	            else 
	            {
    	            //DO NOTHING
    	            return message;
	            }
	        }
	        else 
	        {
    	        //DO NOTHING
    	        return message;
	        }
	}
	
    private String encodeDecodeWcf(String strEncodeDecode, String strBase64Content)
    {
        try 
        {
            String line;
            String out;
            String[] commandWithArgs = { "NBFS.exe" , strEncodeDecode, strBase64Content };
            Process p = Runtime.getRuntime().exec(commandWithArgs);
            BufferedReader input = new BufferedReader(new InputStreamReader(p.getInputStream()));
            if ((line = input.readLine()) != null) {
                out = line;
            } 
            else 
            {
                out = "An Error Has Occurred";
            }
            input.close();
            return out;
        }
        catch (Exception err) 
        {
            return err.getMessage();
        }
    }
  
	public static String removeHttpHeader(String strHttpHeaders,String strPattern)
	{
		strHttpHeaders = strHttpHeaders.replaceAll(strPattern, "");
		return strHttpHeaders;
	}


	public static String updateContentLength (String strHttpHeaders,int length)
	{
		strHttpHeaders = strHttpHeaders.replaceAll("(Content-Length: )(\\d+)","$1" + length);
		return strHttpHeaders;
	}
}


