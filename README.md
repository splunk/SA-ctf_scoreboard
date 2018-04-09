
# SA-ctf_scoreboard
A capture the flag scoreboard app for Splunk.

This app, along with its companion [admin app](https://github.com/splunk/SA-ctf_scoreboard_admin), allows anyone to run their own jeopardy-style capture the flag (CTF) events. These are the same apps that we at splunk use to run our popular [Spunk Boss of the SOC (BOTS)](https://www.splunk.com/blog/2017/09/06/what-you-need-to-know-about-boss-of-the-soc.html) and Boss of the NOC (BOTN) competitions. The apps include the following features:
  * User/team management
  * Scoring management
  * Comprehensive scoring analytics
  * Fully customizable question/answer sets
  * Hint management
 
The scoring apps run on Splunk Enterprise. If you do not have a Splunk license, these apps can run with full functionality on the Enterprise Trial version of Splunk available at 

## Installation
1.	Install Splunk Enterprise 
    * The apps are designed to run on Linux and/or Mac OSX; they have never been tested on Splunk for Windows (Note: Tested with Splunk Enterprise version 7.0.3)
    * Download Splunk from [www.splunk.com](https://www.splunk.com/) 
    * Splunk installation instructions for [Linux](http://docs.splunk.com/Documentation/Splunk/7.0.3/Installation/InstallonLinux) and [Mac OSX](http://docs.splunk.com/Documentation/Splunk/7.0.3/Installation/InstallonMacOS) 
    * Set a strong password for the Splunk admin user
    * Set the Splunk timezone for the admin user
    * [Enable HTTPS](http://docs.splunk.com/Documentation/Splunk/7.0.3/Security/TurnonbasicencryptionwithSplunkWeb) on Splunk Web
   
 2. Set the $SPLUNK_HOME environment variable
    * The default location for Splunk is "/opt/splunk" but yours *may* be different
    * Assuming the default, this command will se the environment variable approprioately.
       ```
      export SPLUNK_HOME=/opt/splunk
      ```
2.	Install the following pre-requisite Splunk apps and add-ons
      * [Lookup File Editor app](https://splunkbase.splunk.com/app/1724/) (Note: Tested with version 2.7.0)
      * [Parallel Coordinates Custom Visualization](https://splunkbase.splunk.com/app/3137/) (Tested with version 1.10)
      * [Simple Timeseries Custom Visualization](https://splunkbase.splunk.com/app/3436/) (Tested with version 1.0)
      * [Timeline Custom Visualization](https://splunkbase.splunk.com/app/3120/) (Tested with version 1.2.0)

3.	Install the [CTF Scoreboard app](https://github.com/daveherrald/SA-ctf_scoreboard)
    ```
    cd $SPLUNK_HOME/etc/apps
    git clone https://github.com/splunk/SA-ctf_scoreboard
    ```

4.	Install the [CTF Scoreboard Admin app](https://github.com/daveherrald/SA-ctf_scoreboard_admin)
    ```
    cd $SPLUNK_HOME/etc/apps
    git https://github.com/splunk/SA-ctf_scoreboard_admin
    ```
