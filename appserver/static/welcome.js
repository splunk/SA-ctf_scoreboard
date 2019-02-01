require(["underscore",
         "jquery",
         "splunkjs/mvc",
         "splunkjs/mvc/utils",
         "splunkjs/mvc/searchmanager",
         "bootstrap.popover",
         "bootstrap.tooltip",
         "splunkjs/mvc/simplexml/ready!"], function(_, $, mvc, utils, SearchManager){

  $("[data-toggle=popover]").popover();
  $("[data-toggle=tooltip]").tooltip();
  var tokens = mvc.Components.get("default");
  var user=Splunk.util.getConfigValue("USERNAME");

  var enableStealthSearch = '| makeresults | eval user="' + user + '" `get_user_info_real` | eval StealthModeTeam="stealth-".upper(substr(sha1(tostring(random(),"HEX")), -6)) | table Team StealthModeTeam | inputlookup ctf_stealth append=true | dedup Team | dedup StealthModeTeam | outputlookup ctf_stealth';
  var disableStealthSearch = '| makeresults | eval user="' + user + '" `get_user_info_real` | eval TeamToDelete=Team | inputlookup ctf_stealth append=true | eventstats first(TeamToDelete) as TeamToDelete | where NOT TeamToDelete = Team | table StealthModeTeam Team | outputlookup ctf_stealth';
  var refreshStealthSearch = '| makeresults | eval user="' + user + '" `get_user_info_real` | lookup ctf_stealth Team | search StealthModeTeam=* | stats last(StealthModeTeam) as StealthModeTeam, count | eval StealthMode=if(count>0,"Enabled (".StealthModeTeam.")","Disabled")';
  var acceptUserAgreementSearch = '| inputlookup ctf_eulas | search EulaDefault=1 | head 1 | eval EulaUsername="' + user + '" | eval EulaDateAccepted=now() | fields EulaId, EulaName, EulaUsername, EulaDateAccepted | outputlookup append=true ctf_eulas_accepted';
  var refreshUserAgreementSearch = '| makeresults | eval user="' + user + '" `get_user_info_real`';
  var refreshUserAgreementSearch = '| makeresults | eval user="' + user + '" `get_user_info_real`';

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

   var sm3 = new SearchManager({
    "id": 'refreshAgreement',
    "cancelOnUnload": true,
    "latest_time": "",
    "status_buckets": 0,
    "earliest_time": "0",
    "search": refreshUserAgreementSearch,
    "app": utils.getCurrentApp(),
    "preview": true,
    "runWhenTimeIsUndefined": false,
    "autostart": true
    }, { tokens: true, tokenNamespace: "submitted" });
 
    sm3.on('search:done', function(properties) {
         var searchName = properties.content.request.label
         if (properties.content.resultCount == 0) {
         } else {
             var results = splunkjs.mvc.Components.getInstance(searchName).data('results', { output_mode: 'json', count: 0 });
             results.on("data", function(properties) {
                 var searchName = properties.attributes.manager.id
                 var data = properties.data().results
                 tokens.set("ctf_agreement_accepted", data[0]['EulaAccepted']);
             });
         };
     });

   var sm4 = new SearchManager({
    "id": 'acceptUserAgreement',
    "cancelOnUnload": true,
    "latest_time": "",
    "status_buckets": 0,
    "earliest_time": "0",
    "search": acceptUserAgreementSearch,
    "app": utils.getCurrentApp(),
    "preview": true,
    "runWhenTimeIsUndefined": false,
    "autostart": false
    }, { tokens: true, tokenNamespace: "submitted" });
 
    sm4.on('search:done', function(properties) {
     sm3.startSearch();
    });

    var sm5 = new SearchManager({
      "id": 'retrieveUserAgreement',
      "cancelOnUnload": true,
      "latest_time": "",
      "status_buckets": 0,
      "earliest_time": "0",
      "search": '| inputlookup ctf_eulas | search EulaDefault=1 | head 1',
      "app": utils.getCurrentApp(),
      "preview": true,
      "runWhenTimeIsUndefined": false,
      "autostart": true
      }, { tokens: true, tokenNamespace: "submitted" });
   
    sm5.on('search:done', function(properties) {
        var searchName = properties.content.request.label
        if (properties.content.resultCount == 0) {
        } else {
            var results = splunkjs.mvc.Components.getInstance(searchName).data('results', { output_mode: 'json', count: 0 });
            results.on("data", function(properties) {
                var searchName = properties.attributes.manager.id
                var data = properties.data().results
                tokens.set("ctf_eula_content", data[0]['EulaContent']);
            });
        };
    });

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

    $("#agreement_modal_button").click(function() {
      // The require will let us tell the browser to load Modal.js with the name "Modal"
      require(['jquery', "/static/app/SA-ctf_scoreboard/Modal.js"
      ], function($,
          Modal) {
          // Now we initialize the Modal itself
          var myModal = new Modal("userAgreementModal", {
              title: "User Agreement",
              backdrop: 'static',
              keyboard: false,
              destroyOnHide: true,
              type: 'normal'
          });
          myModal.body
              .append($('<pre>' + tokens.get("ctf_eula_content") + '</pre>'));
          myModal.footer.append($('<button>').attr({
              type: 'button',
              'data-dismiss': 'modal'
          }).addClass('btn').text('Accept Agreement').on('click', function() {
              sm4.cancel();
              sm4.settings.set("search", acceptUserAgreementSearch); 
              sm4.startSearch();
          }))
          myModal.show(); // Launch it!
      })
  })
});

