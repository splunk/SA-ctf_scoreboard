require(["underscore",
         "jquery",
         "splunkjs/mvc",
         "splunkjs/mvc/utils",
         "splunkjs/mvc/searchmanager",
         "splunkjs/mvc/simplexml/ready!"], function(_, $, mvc, utils, SearchManager){

  var tokens = mvc.Components.get("default");
  var user=Splunk.util.getConfigValue("USERNAME");

  var enableStealthSearch = '| makeresults | eval user="' + user + '" `get_user_info_real` | eval StealthModeTeam="stealth-".upper(substr(sha1(tostring(random(),"HEX")), -6)) | table Team StealthModeTeam | inputlookup ctf_stealth append=true | dedup Team | dedup StealthModeTeam | outputlookup ctf_stealth';

  var disableStealthSearch = '| makeresults | eval user="' + user + '" `get_user_info_real` | eval TeamToDelete=Team | inputlookup ctf_stealth append=true | eventstats first(TeamToDelete) as TeamToDelete | where NOT TeamToDelete = Team | table StealthModeTeam Team | outputlookup ctf_stealth';

  var refreshStealthSearch = '| makeresults | eval user="' + user + '" `get_user_info_real` | lookup ctf_stealth Team | search StealthModeTeam=* | stats last(StealthModeTeam) as StealthModeTeam, count | eval StealthMode=if(count>0,"Enabled (".StealthModeTeam.")","Disabled")';

  $("#enable_stealth_button").click(function() {
    sm2.cancel();
    sm2.settings.set("search", enableStealthSearch); 
    sm2.startSearch();
  });

  $("#disable_stealth_button").click(function() {
    sm2.cancel();
    sm2.settings.set("search", disableStealthSearch); 
    sm2.startSearch();
  });

  $("#refresh_stealth_button").click(function() {
    sm.cancel();
    sm.settings.set("search", refreshStealthSearch); 
    sm.startSearch();
  });

  var sm = new SearchManager({
   "id": 'readStealthStatus',
   "cancelOnUnload": true,
   "latest_time": "",
   "status_buckets": 0,
   "earliest_time": "0",
   "search": refreshStealthSearch,
   "app": utils.getCurrentApp(),
   "preview": true,
   "runWhenTimeIsUndefined": false,
   "autostart": true
   }, { tokens: true, tokenNamespace: "submitted" });

   sm.on('search:done', function(properties) {
        var searchName = properties.content.request.label
        if (properties.content.resultCount == 0) {
          console.log("No results found.");
        } else {
            var results = splunkjs.mvc.Components.getInstance(searchName).data('results', { output_mode: 'json', count: 0 });
            results.on("data", function(properties) {
                var searchName = properties.attributes.manager.id
                var data = properties.data().results
                tokens.set("ctf_stealth_mode", data[0]['StealthMode']);
            });
        };
    });

  var sm2 = new SearchManager({
   "id": 'writeStealthStatus',
   "cancelOnUnload": true,
   "latest_time": "",
   "status_buckets": 0,
   "earliest_time": "0",
   "search": refreshStealthSearch,
   "app": utils.getCurrentApp(),
   "preview": true,
   "runWhenTimeIsUndefined": false,
   "autostart": true
   }, { tokens: true, tokenNamespace: "submitted" });

   sm2.on('search:done', function(properties) {
    sm.startSearch();
   });
});

