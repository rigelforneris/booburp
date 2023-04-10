# booburp

A burp plugin to parse a request and transforms in a boofuzz python script!

Instructions:

There is a file called jython-standalone-2.7.3.jar located in root directory of this project, this is Jython, a python enviroment for java, copy to a place of your choose.

On burp, in extentions tab, go to "extention settings", in python enviroment, put the location of jython in "location of jython standalone JAR file".

this plugins isn't in the BApp Store yet, so you need to add manually: In Extensions tab, go to "add" to add the burp extention and you are ready!

you need to install boofuzz if you want to run the boofuzz scripts that the plugin creates: pip install boofuzz