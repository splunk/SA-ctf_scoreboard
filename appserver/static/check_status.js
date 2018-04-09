var refresh_rate = 10
console.log("Started")
require([
    "jquery",
    "underscore",
    "splunkjs/mvc",
    "splunkjs/mvc/utils",
    "splunkjs/mvc/tokenutils",
    "splunkjs/mvc/simplexml",
    "splunkjs/mvc/searchmanager",
    "splunkjs/ready!"
    ],
    function(
        $,
        _,
        mvc,
        utils,
        TokenUtils,
        DashboardController,
        SearchManager,
        Ready
        ) {

        
        console.log("In our code")

                    var StatusCheckSearch = new SearchManager({
                        "id": "statusSearch",
                        "cancelOnUnload": true,
                        "latest_time": "",
                        "status_buckets": 0,
                        "earliest_time": "0",
                        "search": " | inputlookup ctf_status_messages.csv | sort - _time | search color=* | where _time > (now() - " + refresh_rate + ")| table color | head 1 | appendcols [| inputlookup ctf_status_messages.csv  | sort - _time | where _time > (now() - " + refresh_rate + ") | search message=* | stats values(message) as messages first(messagecolor) as messagecolor | eval messages=mvjoin(messages, \"; \")]",
                        "app": "search",
                        "auto_cancel": 20,
                        "preview": true,
                        "runWhenTimeIsUndefined": false,
                        "refresh": refresh_rate,
                        "autostart": true
                    }, {tokens: true, tokenNamespace: "submitted"});

                
                    var StatusCheckSearchResults = StatusCheckSearch.data('results', { output_mode:'json', count:0 });

                    StatusCheckSearch.on('search:error', function(properties) {
                        console.log("Search Error", properties);
                    });
                    StatusCheckSearch.on('search:failed', function(properties) {
                        console.log("Search Error", properties);
                    });
                    StatusCheckSearch.on('search:done', function(properties) {
                        console.log("Got Results from Data Check Search", properties);

                        if(StatusCheckSearch.attributes.data.resultCount == 0) {
                            console.log("No Results from Data Check Search" , properties);
                          return;
                        }       

                        StatusCheckSearchResults.on("data", function(properties) {
                            console.log("Data Check -- here's my check for myResults...", properties)
                        
                            
                            var data = StatusCheckSearchResults.data().results;
                            console.log("Got Data from Data Check Search", data, properties);
                            var color = data[0].color

                            var message = ""
                            var messagecolor = "black"
                            if( "messages" in data[0]){
                                var messagecolor = data[0].messagecolor
                            }
                            if( "messages" in data[0]){
                                var message = data[0].messages
                                setMessage(message, messagecolor)
                            }
                                
                            setColor(color)
                            
                            
                        
                        });
                      });




    });


function setMessage(message, messagecolor){
    $("body").append("<div id='centermeman' style=\"color: " + messagecolor + "\">" + message + "</div>")
    $("#centermeman").css("position", "absolute")
    $("#centermeman").css('left', $(window).width()/2 - $("#centermeman").width()/2);
    $("#centermeman").css('top', 0);
    setTimeout(function(){
        
        $("#centermeman").remove()
        $("#centermeman").attr("id", "Iamdeadnow!")
    },Math.round(refresh_rate * .6 * 1000))
}


function setColor(color){
    $("body").css("border", "rgb(" + color + ") 20px solid");
setTimeout(function(){

    var div = $('body');
    $({alpha:1}).animate({alpha:0}, {
        duration: Math.round(refresh_rate * .375 * 1000),
        step: function(){
            div.css('border-color','rgba(' + color + ','+this.alpha+')');
   div.css('border-width',Math.floor(this.alpha * 20) +'px');
   //console.log("alpha", this.alpha)
        }
    });

}, Math.round(refresh_rate * .375 * 1000));
}