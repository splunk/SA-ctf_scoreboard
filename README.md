
# SA-ctf_scoreboard
A capture the flag scoreboard app for Splunk.

This app, along with its companion [admin app](https://github.com/splunk/SA-ctf_scoreboard_admin), allows anyone to run their own jeopardy-style capture the flag (CTF) events. These are the same apps that we at Splunk use to run our popular [Splunk Boss of the SOC (BOTS)](https://www.splunk.com/blog/2017/09/06/what-you-need-to-know-about-boss-of-the-soc.html) and Boss of the NOC (BOTN) competitions. The apps include the following features:
  * User/team management
  * Scoring management
  * Comprehensive scooreboards, dashboards, and analytics
  * Fully customizable question/answer management
  * Hint management
 
The scoring apps run on Splunk Enterprise. If you do not have a Splunk license, these apps can run with full functionality on the Enterprise Trial version of Splunk available at [www.splunk.com](https://www.splunk.com)

## Installation
1.	Install Splunk Enterprise 
  * The apps are designed to run on Linux and/or Mac OSX; they have never been tested on Splunk for Windows (Note: Tested with Splunk Enterprise version 7.0.3)
  * Download Splunk from [www.splunk.com](https://www.splunk.com/) 
  * Refer to Splunk installation instructions for [Linux](http://docs.splunk.com/Documentation/Splunk/7.0.3/Installation/InstallonLinux) and [Mac OSX](http://docs.splunk.com/Documentation/Splunk/7.0.3/Installation/InstallonMacOS) as necessary 
  * Set a strong password for the Splunk admin user
  * Set the Splunk timezone for the admin user
  * [Enable HTTPS](http://docs.splunk.com/Documentation/Splunk/7.0.3/Security/TurnonbasicencryptionwithSplunkWeb) on Splunk Web
   
 2. Set the $SPLUNK_HOME environment variable
  * The default location for Splunk is "/opt/splunk" but yours *may* be different
  * Assuming the default, this command will se the environment variable approprioately:
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
    git clone https://github.com/splunk/SA-ctf_scoreboard_admin
    ```
5.	Restart Splunk to recognize all the pre-requisites and the scoring apps
    ```
    $SPLUNK_HOME/bin/splunk restart
    ```
7.	Create scoreboard log directory 
    ```
    mkdir $SPLUNK_HOME/var/log/scoreboard
    ```
8.	Create the CTF Answers service account in Splunk
  * By convention this user is called cabanaboy because that’s what any rational person would pick while sitting next to Ryan Kovar
  * Pick a good strong password, and record it. You will need it again soon. The good news is that it does not need to be easily memorized by a human.
  * Assign the cabanaboy user to role ctf_answers_service
  * This can all be accomplished from the command line as follows:
    ```
     $SPLUNK_HOME/bin/splunk add user cabanaboy -password <password> -role ctf_answers_service -auth admin:changeme
    ```
 9.	Configure the custom controller 
    ```
    cd $SPLUNK_HOME/etc/apps/SA-ctf_scoreboard/appserver/controllers
    cp scoreboard_controller.config.example scoreboard_controller.config
    ```

  * Edit scoreboard_controller.config to refelct the following 
  * The  CTF Answers service account username (probably cabanaboy) 
  * The  CTF Answers service account password you chose above
  * A vkey parameter which should just be a random string, 10-20 characters in length
  * Note scoreboard_controller.config is prevented via .gitignore from being checked into the git repository. Only the example file is included in the repository.

10. Restart Splunk to recognize the changes to the controller configuration file.
    ```
    $SPLUNK_HOME/bin/splunk restart
    ```

11.	Confirm the custom controller came up properly: 
   ```
    ls -l $SPLUNK_HOME/var/log/scoreboard
    -rw------- 1 splunk staff 59 Sep 2 14:26 scoreboard.log
    -rw------- 1 splunk staff 59 Sep 2 14:26 scoreboard_admin.log
   ```

12.	Set up an admin user 
  * It does not need to be *the* Splunk admin user, but it can be and often is
  * In Splunk Web ensure the admin user has been assigned the following roles: 
  * admin
  * ctf_admin
  * can_delete
    
13. Load sample data
  * Log in as the admin user created above
  * Navigate to Capture the Flag Admin app
  * Click each of the following menu items in turn:
    * Data Management...->Load SAMPLE data (DANGER)->Load sample users/teams
    * Data Management...->Load SAMPLE data (DANGER)->Load sample questions
    * Data Management...->Load SAMPLE data (DANGER)->Load sample answers
    * Data Management...->Load SAMPLE data (DANGER)->Load sample hints
    * Data Management...->Load SAMPLE data (DANGER)->Load sample hint entitlements
    * Data Management...->Load SAMPLE data (DANGER)->Load sample badges
    * Data Management...->Load SAMPLE data (DANGER)->Load sample badge entitlements

14. Set the start / end time of the questions in the competition
  * Though not required, it is easiest if you set both your computer time zone, AND the Splunk time zone for the user you are logged in as to the main time zone of the event
  * In the CTF Admin app Go to Edit->Time Setup
  * Follow the instructions embedded in the dashboard. In Step 0, first ensure you have the proper question set loaded, and make sure the start and end times need adjusting. This is accomplished by visually inspecting the bottom panel.
  * Assuming the questions look right, and the times need adjusting
  * Populate the start and end dates/times. If you set your computer and Splunk TZ as suggested in an earlier step, you will likely not have to worry about the TZ setting in the pull-down.
  * Click green “Submit Changes” button.
  * Check that “Question Summary” panel at the bottom for sanity.
  * Verify the start/end times by visiting View -> Q&A and inspecting the NiceStarttime and NiceEndTime columns.



        
