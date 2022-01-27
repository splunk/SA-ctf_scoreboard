
# SA-ctf_scoreboard
A capture the flag scoreboard app for Splunk.

NOTE: As of January 2022, this app has been deprecated. Please visit https://bots.splunk.com for hands-on experiences using Splunk security products. Splunk will no longer provide assistance or support for this app.

This app, along with its companion [admin app](https://github.com/splunk/SA-ctf_scoreboard_admin), allows anyone to run their own jeopardy-style capture the flag (CTF) events. These are the same apps that we at Splunk use to run early versions of our popular [Splunk Boss of the SOC (BOTS)](https://www.splunk.com/blog/2017/09/06/what-you-need-to-know-about-boss-of-the-soc.html) competitions. The apps include the following features:
  * User/Team management
  * Scoring management
  * Question/Answer management
  * Hint management
  * Comprehensive scoreboards, dashboards, and analytics
 
The scoring apps run on Splunk Enterprise. If you do not have a Splunk license, these apps can run with full functionality on the Enterprise Trial version of Splunk available at [www.splunk.com](https://www.splunk.com)

## Related Projects
  * [Boss of the SOC Version 1 (botsv1) data set](https://github.com/splunk/botsv1)
  * Boss of the SOC Version 1 (botsv1) questions, answers, hints. Please contact bots \<at\> splunk.com for access to these resources.


## Installation
1.	Install Splunk Enterprise 
  * The apps are designed to run on Linux and/or Mac OSX; they have never been tested on Splunk for Windows (Note: This app requires Splunk Enterprise version 8.2.x)
  * Download Splunk from [www.splunk.com](https://www.splunk.com/) 
  * Refer to Splunk installation instructions for [Linux](http://docs.splunk.com/Documentation/Splunk/7.0.3/Installation/InstallonLinux) and [Mac OSX](http://docs.splunk.com/Documentation/Splunk/7.0.3/Installation/InstallonMacOS) as necessary 
  * Set a strong password for the Splunk admin user
  * Set the time zone for the admin user via Splunk Web
  * [Enable HTTPS](http://docs.splunk.com/Documentation/Splunk/7.0.3/Security/TurnonbasicencryptionwithSplunkWeb) on Splunk Web
   
 2. Set the $SPLUNK_HOME environment variable
  * The default location for Splunk is "/opt/splunk" but yours *may* be different
  * Assuming the default, this command will set the environment variable appropriately:
       ```
      export SPLUNK_HOME=/opt/splunk
      ```
2.	Install the following prerequisite Splunk apps and add-ons
  * [Lookup File Editor app](https://splunkbase.splunk.com/app/1724/) (Note: Tested with version 3.0.3)
  * [Parallel Coordinates Custom Visualization](https://splunkbase.splunk.com/app/3137/) (Note: Tested with version 1.2.0)
  * [Simple Timeseries Custom Visualization](https://splunkbase.splunk.com/app/3436/) (Note: Tested with version 1.0)
  * [Timeline Custom Visualization](https://splunkbase.splunk.com/app/3120/) (Note: Tested with version 1.2.0)

3.	Install the [CTF Scoreboard app](https://github.com/splunk/SA-ctf_scoreboard)
    ```
    cd $SPLUNK_HOME/etc/apps
    git clone https://github.com/splunk/SA-ctf_scoreboard
    ```

4.	Install the [CTF Scoreboard Admin app](https://github.com/splunk/SA-ctf_scoreboard_admin)
    ```
    cd $SPLUNK_HOME/etc/apps
    git clone https://github.com/splunk/SA-ctf_scoreboard_admin
    ```
5.	Restart Splunk to recognize all the prerequisites and the scoring apps
    ```
    $SPLUNK_HOME/bin/splunk restart
    ```
7.	Create scoreboard log directory 
    ```
    mkdir $SPLUNK_HOME/var/log/scoreboard
    ```
8.	Create the CTF Answers service account in Splunk
  * By convention this user is called svcaccount
  * Pick a good strong password, and record it. You will need it again soon. The good news is that it does not need to be easily memorized by a human.
  * Assign the svcaccount user to role ctf_answers_service
  * This can all be accomplished from the command line as follows:
    ```
     $SPLUNK_HOME/bin/splunk add user svcaccount -password <password> -role ctf_answers_service -auth admin:<admin_password>
    ```
 9.	Configure the custom controller 
    ```
    cd $SPLUNK_HOME/etc/apps/SA-ctf_scoreboard/appserver/controllers
    cp scoreboard_controller.config.example scoreboard_controller.config
    ```

  * Edit scoreboard_controller.config to reflect the following:
  * The CTF Answers service account username (probably svcaccount) 
  * The CTF Answers service account password you chose above
  * A vkey parameter which should just be a random string, 10-20 characters in length
  * Note: scoreboard_controller.config is prevented via .gitignore from being checked into the git repository. Only the example file is included in the repository.

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
    * Data Management...->Load SAMPLE data (DANGER)->Load sample user agreements

  * It's not _really_ dangerous, but it will overwrite the data you currently have loaded in the game.

14. Customize your questions/answers/hints

Use the items on the Edit menu to customize the game to your liking.

Alternatively, follow these instructions to load the Splunk BOTS questions, answers, and hints
  * Obtain the following three files: ctf_questions.csv, ctf_answers.csv, ctf_hints.csv
  * Navigate to Capture the Flag Admin app
  * Load questions
    1. Edit -> Edit Questions
    2. Click the Import button in the upper right
    3. Click Select file to import
    4. Select the ctf_questions.csv file
  * Load answers   
    1. Edit -> Edit Answers
    2. Click the Import button in the upper right
    3. Click Select file to import
    4. Select the ctf_answers.csv file
  * Load hints
    1. Edit -> Edit Hints
    2. Click the Import button in the upper right
    3. Click Select file to import
    4. Select the ctf_hints.csv file
  * Check that the questions/answers were loaded properly
    1. Navigate to Capture the Flag Admin app
    2. View -> Q & A
    3. Visually inspect the Questions and Answers    
  
15. Set the start / end time of the questions in the competition
  * Though not required, it is easiest if you set both your computer time zone, AND the Splunk time zone for the user you are logged in as to the main time zone of the event
  * In the CTF Admin app Go to Edit->Time Setup
  * Follow the instructions embedded in the dashboard. In Step 0, first ensure you have the proper question set loaded. Review your start and end times to determine if they need to be adjusted. This is accomplished by visually inspecting the bottom panel.
  * If the questions look right, but the times need adjusting
    * Populate the start and end dates/times in the GUI. If you set your computer and Splunk TZ as suggested in an earlier step, you will likely not have to worry about the TZ setting in the pull-down.
    * Click green “Submit Changes” button.
  * Check that “Question Summary” panel at the bottom for sanity.
  * Verify the start/end times by visiting View -> Q&A and inspecting the NiceStartTime and NiceEndTime columns.
  
16.	Disable access to the questions for the ctf_competitor role.
  * Go to CTF Admin app and load Edit->Question Access dashboard.
  * The current status of questions will be displayed. Disable access until immediately before you are ready to begin the competition, then enable it.
  
## Clearing Results
To clear all activity from the scoring app, perform these steps. 

WARNING: Running these commands will permanenently delete all the activity from the app and reset all scores to zero.

```
$SPLUNK_HOME/bin/splunk stop
$SPLUNK_HOME/bin/splunk clean eventdata -f scoreboard
$SPLUNK_HOME/bin/splunk clean eventdata -f scoreboard_admin
rm $SPLUNK_HOME/var/log/scoreboard/scoreboard.log
rm $SPLUNK_HOME/var/log/scoreboard/scoreboard_admin.log
$SPLUNK_HOME/bin/splunk start
```
  
## Authors
Written in 2016-2018 by David Herrald and Ryan Kovar, with contributions from Brad Lindow, James Brodsky, David Veuve, John Stoner, Steve Brant, Jesse Trucks, Lily Lee, Jon Lebaugh, Bill Babillon, Luke Murphey, Filip Wijnholds, and others.

## Copyright and License
To the extent possible under law, the author(s) have dedicated
all copyright and related and neighboring rights to this software
to the public domain worldwide. This software is distributed
without any warranty. You should have received a copy of the CC0
Public Domain Dedication along with this software. If not, see
http://creativecommons.org/publicdomain/zero/1.0/.

 
### Special Copyright/License Notes

The following files are included from the [Splunk 6.x Dashboard Examples app](https://splunkbase.splunk.com/app/1603/) version 6.6.1 and are subject to the licenses included therein.
 * appserver/static/custom_table_row_expansion.js
 * appserver/static/table_icons_inline.js
 * appserver/static/table_decorations.css 
