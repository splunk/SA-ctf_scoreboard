require([
    'underscore',
    'jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/tableview',
    'splunkjs/mvc/simplexml/ready!'
], function(_, $, mvc) {
    var defaultTokens = mvc.Components.get("default"); 
    var submittedTokens = mvc.Components.get("submitted"); 
    var tokens = {
        get: function(tokenName) {
            return defaultTokens.get(tokenName);
        },
    
        set: function(tokenName, tokenValue) {
            defaultTokens.set(tokenName, tokenValue);
            submittedTokens.set(tokenName, tokenValue);
        }, 
        on: function(eventName, callback) { 
            defaultTokens.on(eventName, callback); 
        }
    };
    var Result=tokens.get('Result');
    var BasePointsAwarded = tokens.get('BasePointsAwarded');
    var SpeedBonusAwarded = tokens.get('SpeedBonusAwarded');
    var Penalty = tokens.get('Penalty');
    var AdditionalBonusAwarded = tokens.get('AdditionalBonusAwarded');
    var SolicitBonusInfo = tokens.get('SolicitBonusInfo');

    document.getElementById('ViewDetails').onclick = function(){tokens.set('ViewDetails', true);}

    var CTFResultTable = document.getElementById('ResultTable');

    var AdditionalNotes = document.getElementById('AdditionalNotes')

    if (Result == 'Correct'){
        document.getElementById('Result1').innerHTML = '<span class="Correct"> Correct! </span>';
        
        InsRow(CTFResultTable, "Base Points Earned", BasePointsAwarded);
        InsRow(CTFResultTable, "Speed Bonus Points Earned", SpeedBonusAwarded);

        AdditionalNotes.innerHTML = 'Note:  Regardless of the result shown above, your team will not be awarded points for answering the same question correctly multiple times.';

    }

    if (Result == 'Incorrect'){
        document.getElementById('Result1').innerHTML = '<span class="Incorrect"> Incorrect </span>';

        InsRow(CTFResultTable, "Penalty Points Assessed", Penalty)

        AdditionalNotes.innerHTML = "To attempt this question again, just click the 'back' button in your browser.";

    }

    if (Result == 'Bonus'){
        document.getElementById('Result1').innerHTML = '<span class="Bonus"> Thanks! </span>';
        InsRow(CTFResultTable, "Bonus Points", AdditionalBonusAwarded)

        AdditionalNotes.innerHTML = 'Note:  Regardless of the result shown above, your team will not be awarded points for submitting additional bonus information multiple times.';


    }


    if (SolicitBonusInfo != '1' || Result != 'Correct'){ 
            document.getElementById('BonusInfo').innerHTML = '';
    }

    function InsRow(table, col1, col2){
        newRow = table.insertRow(-1);
        newCell1 = newRow.insertCell(-1);
        newCell2 = newRow.insertCell(-1);

        newCell1.innerHTML = col1;
        newCell2.innerHTML = col2;
    }

});
