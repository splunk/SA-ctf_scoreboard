require([
    'underscore',
    'jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/tableview',
    'splunkjs/mvc/simplexml/ready!'
], function(_, $, mvc, TableView) {
    var CustomIconRenderer = TableView.BaseCellRenderer.extend({
        canRender: function(cell) {
            return cell.field === 'Status';
        },
        render: function($td, cell) {
            var status = cell.value;
            // Compute the icon base on the field value
            var icon;
            var color;
            if(status === "Correct" ) {
                icon = 'box-checked';
                color = '#5CC05C';
            } else if(status === "Incorrect" ) {
                icon = 'error';
                color = '#DC4E41';
            } else {
                icon = 'box-unchecked';
                color = '#00A4FD';
            }
            // Create the icon element and add it to the table cell
            $td.addClass('icon-inline').html(_.template('<i style="color: <%-color%>;" class="icon-<%-icon%>"></i>&nbsp;<%- text %>', {
                icon: icon,
                color: color,
                text: cell.value
            }));
        }
    });
    mvc.Components.get('table1').getVisualization(function(tableView){
        // Register custom cell renderer, the table will re-render automatically
        tableView.addCellRenderer(new CustomIconRenderer());
    });
});
