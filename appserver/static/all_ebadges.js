require([
    'underscore',
    'jquery',
    'splunkjs/mvc',
    'splunkjs/mvc/tableview',
    'splunkjs/mvc/simplexml/ready!'
], function(_, $, mvc, TableView) {
    var CustomTableImageRenderer = TableView.BaseCellRenderer.extend({
        canRender: function(cell) {
            return cell.field === 'BadgeURL' || cell.field === 'Team' || cell.field === 'BadgeName' || cell.field === 'Unique Count';
        },
        render: function($td, cell) {
            if (cell.field === 'BadgeURL') {
                badge_list = cell.value.split(",");
                prepared_html = '<div class="badge-image-row">';
                badge_list.forEach(function(badge){
                    prepared_html += '<img class="badge-image" src="' + badge.trim() + '" />';
                }); 
                prepared_html += '</div>';
                $td.html(prepared_html);
            }
            if (cell.field === 'Team' || cell.field === 'Unique Count' || cell.field === 'BadgeName' ) {
                prepared_html = '<div class="team-text">' + cell.value + '</div>';
                console.log(prepared_html);
                $td.html(prepared_html);
            }
        }
    });
    mvc.Components.get('badge_table').getVisualization(function(tableView){
        // Register custom cell renderer, the table will re-render automatically
        tableView.addCellRenderer(new CustomTableImageRenderer());
    });
});