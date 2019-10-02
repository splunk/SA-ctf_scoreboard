require(["jquery",
         "splunkjs/mvc/utils",
         "splunkjs/mvc/searchmanager",
         "/static/app/SA-ctf_scoreboard/jquery.countdown.js",
         "splunkjs/ready!",
         "splunkjs/mvc/simplexml/ready!"], function($, utils, SearchManager){

  // Set panel widths to 75/25
  var firstRow = $('.dashboard-row').first();
  var panelCells = $(firstRow).children('.dashboard-cell');
  $(panelCells[0]).css('width', '15%');
  $(panelCells[1]).css('width', '70%');
  $(panelCells[2]).css('width', '15%');

  // Detemine competition end time and start the clock.
  var sm = new SearchManager({
    "id": 'getEndTimeSM',
    "cancelOnUnload": true,
    "latest_time": "",
    "status_buckets": 0,
    "earliest_time": "0",
    "search": "|inputlookup ctf_questions | stats max(EndTime) as EndTime | fields + EndTime",
    "app": utils.getCurrentApp(),
    "preview": true,
    "runWhenTimeIsUndefined": false,
    "autostart": true
    }, { tokens: true, tokenNamespace: "submitted" });

    sm.on('search:done', function(properties) {
        var searchName = properties.content.request.label
        if (properties.content.resultCount == 0) {
            console.log(searchName, "gave no results, so timer cannot be started.", properties)
        } else {
            var results = splunkjs.mvc.Components.getInstance(searchName).data('results', { output_mode: 'json', count: 0 });
            results.on("data", function(properties) {
                var searchName = properties.attributes.manager.id
                var data = properties.data().results
                epoch = parseInt(data[0]['EndTime'],10);
                var d = new Date(0);
                d.setUTCSeconds(epoch);
                // Instantiate the countdown timer with the time of the last question in ctf_questions.
                $('#clock').countdown(d, function(event) {
                    $(this).html(event.strftime('%D:%H:%M:%S'));
                  });
            });
        };
    });
});

