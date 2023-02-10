import { analysisTableDefs, analysisSubTableDefs } from "./tableDefs.js"

/*---------GLOBALS---------*/
let active_profile = "";
let active_timewindow = "";
let active_timewindow_index = 0;
let active_tw_id = "";
let active_analysisTable = 'timeline';
let last_analysisTable = 'timeline';

function capitalizeFirstLetter(data) {
    return data.charAt(0).toUpperCase() + data.slice(1);
}

function updateAnalysisTable() {
    if (active_profile && active_timewindow) {
        let link = "/analysis/" + active_analysisTable + "/" + active_profile + "/" + active_timewindow;
        $("#table_" + active_analysisTable).DataTable().ajax.url(link).load();
        removeListeners(last_analysisTable);

        switch (active_analysisTable) {
            case "timeline": {
                initTimelineListeners();
                break;
            }
            case "timeline_flows": {
                initTimelineFlowsListeners();
                break;
            }
            case "alerts": {
                initAlertListeners();
                break;
            }
        }
    }
    document.getElementById(active_analysisTable).style.display = "block";
}

function hideAnalysisTable(tableID) {
    document.getElementById(tableID).style.display = "none";
}

function updateIPInfo(row, field) {
    let data = row.data();
    let url = '/analysis/info/' + data[field];
    $("#table_ipinfo").DataTable().ajax.url(url).load();
}

function addTableEvidence(table_id) {
    let entry = '<table' + ' id="' + table_id + '"' + 'class="table table-striped" cellpadding="5" cellspacing="0" border="0" style="padding-left:50px;">'
    let exit = '</table>'
    let head = "<thead>" +
        "<tr>" +
        "<th>Evidence</th>" +
        "<th>Confidence</th>" +
        "<th>Threat Level</th>" +
        "<th>Category</th>" +
        "<th>Tag</th>" +
        "<th>Description</th>" +
        "</tr>" +
        "</thead>"
    return (entry + head + exit);
}

//function searchReload(filter_parameter){
//    let link = "/analysis/" + active_analysisTable + "/" + active_profile + "/" + active_timewindow
//    if (filter_parameter){ link += "/" + filter_parameter; }
//    $("#table_"+active_analysisTable).DataTable().ajax.url(link).load();
//}

function addTableTWs(tableID) {
    let entry = '<table' + ' id="' + tableID + '"' + ' class="table table-striped" >'
    let exit = '</table>'
    let head = "<thead>" +
        "<tr>" +
        "<th>TW</th>" +
        "</tr>" +
        "</thead>"
    return (entry + head + exit);
};

function hotkeyPress(e) {
    let evtobj = window.event ? event : e
    if (evtobj.keyCode == 78 && evtobj.ctrlKey) {
        let table = $(active_tw_id).DataTable();
        $(table.row(active_timewindow_index).node()).removeClass('row_selected');
        if (active_timewindow_index == table.data().count() - 1) {
            active_timewindow_index = -1
        }
        active_timewindow_index += 1
        $(table.row(active_timewindow_index).node()).addClass('row_selected');
        active_timewindow = table.row(active_timewindow_index).data()["tw"]
        updateAnalysisTable()
    }
    if (evtobj.keyCode == 80 && evtobj.ctrlKey) {
        let table = $(active_tw_id).DataTable();
        $(table.row(active_timewindow_index).node()).removeClass('row_selected');
        active_timewindow_index -= 1;
        if (active_timewindow_index < 0) {
            active_timewindow_index = table.data().count() - 1;
        }
        $(table.row(active_timewindow_index).node()).addClass('row_selected');
        active_timewindow = table.row(active_timewindow_index).data()["tw"]
        updateAnalysisTable()
    }
}

function convertDotToDash(string) {
    return string.replace(/\./g, '_');
}


function addTableAltFlows(data) {
    let start = '<table cellpadding="5" cellspacing="0" border="0" style="padding-left:50px;">'
    let end = '</table>'

    let middle = ""
    for (let [k, v] of Object.entries(data)) {
        middle += '<tr>'
        middle += '<td>' + '<b>' + capitalizeFirstLetter(k) + ':' + '</b>' + '</td>' + '<td>' + v + '</td>'
        middle += '</tr>'
    }
    return start + middle + end
}

/* INITIALIZE LISTENERS FOR TABLES */
/*--------------------------------------------------------------*/
function initHideProfileTWButtonListener() {
    $("#profile-tw-hide-btn").click(function () {

        if (document.getElementById('profiles').style.display === "none") {
            document.getElementById('profiles').style.display = "block";
            document.getElementById('profile-tw-hide-btn').innerHTML = "<";

            $('#col_profiles').removeClass('col-0');
            $('#col_profiles').addClass('col-2');
            $('#col_analysis').removeClass('col-12');
            $('#col_analysis').addClass('col-10');

        } else {
            document.getElementById('profiles').style.display = "none";
            document.getElementById('profile-tw-hide-btn').innerHTML = ">";
            
            $('#col_profiles').removeClass('col-2');
            $('#col_profiles').addClass('col-0');
            $('#col_analysis').removeClass('col-10');
            $('#col_analysis').addClass('col-12');
        }
    });
}

function initAnalysisTagListeners() {
    $("#buttons .btn").click(function () {
        $("#buttons .btn").removeClass('active');
        $(this).toggleClass('active');
        active_analysisTable = $(this).data("tableid");
        updateAnalysisTable();
        if (active_analysisTable != last_analysisTable) {
            hideAnalysisTable(last_analysisTable);
        }
        last_analysisTable = active_analysisTable;
    });
}

function addTableTWsListener(table_tw_id, tr) {
    $("#" + table_tw_id).on('click', 'tbody tr', function () {
        let row = $("#" + table_tw_id).DataTable().row($(this))
        let rowData = row.data();
        let rowIndex = row.index();
        let t = $("#" + table_tw_id).DataTable();
        if (active_tw_id) {
            $($(active_tw_id).DataTable().row(active_timewindow_index).node()).removeClass('row_selected');

        }
        active_tw_id = "#" + table_tw_id
        active_timewindow_index = rowIndex;
        $(t.row(rowIndex).node()).addClass('row_selected');
        active_profile = $("#table_profiles").DataTable().row(tr).data()["profile"]
        active_timewindow = rowData["tw"]
        document.getElementById("active_profile_tw").innerText = "Selected: " + active_profile + " " + rowData["name"];
        updateAnalysisTable()
    });
}

function initProfileTwListeners() {
    $('#table_profiles').on('click', 'tbody td.r', function () {
        let tr = $(this).closest('tr');
        let row = $("#table_profiles").DataTable().row(tr);
        updateIPInfo(row, "profile")

        let profile_id = row.data()['profile']
        let profile_id_dash = convertDotToDash(profile_id)

        if (row.child.isShown()) {
            $("#" + profile_id_dash).DataTable().clear().destroy();
            row.child.hide();
            tr.removeClass('shown');
        }
        else {
            row.child(addTableTWs(profile_id_dash)).show();
            let url = '/analysis/tws/' + profile_id;
            let table_tws = $("#" + profile_id_dash).DataTable(analysisSubTableDefs["tw"]);
            table_tws.ajax.url(url).load();
            addTableTWsListener(profile_id_dash, tr)
            tr.addClass('shown');
        }
    });
}

function initTimelineFlowsListeners() {
    $('#table_timeline_flows').on('click', 'tbody td.saddr', function () {
        let row = $("#table_timeline_flows").DataTable().row($(this).parents('tr'));
        updateIPInfo(row, "saddr")
    })

    $('#table_timeline_flows').on('click', 'tbody td.daddr', function () {
        let row = $("#table_timeline_flows").DataTable().row($(this).parents('tr'));
        updateIPInfo(row, "daddr")
    })
}

function initTimelineListeners() {
    $('#table_timeline').on('click', 'tbody td.daddr', function () {
        let row = $("#table_timeline").DataTable().row($(this).parents('tr'));
        updateIPInfo(row, "daddr")
    })

    //    $('#table_timeline_filter_button').click(function(){
    //        var filter_gender = $('#table_timeline_filter_input').val();
    //        searchReload(filter_gender);
    //    });

    $('#table_timeline').on('click', 'tbody tr', function () {
        let tr = $(this).closest('tr');
        let row = $("#table_timeline").DataTable().row(this)
        let data = row.data()["info"]

        if (data) {
            if (row.child.isShown()) {
                row.child.hide();
                tr.removeClass('shown');
            } else {
                row.child(addTableAltFlows(data)).show();
                tr.addClass('shown');
            }
        }
    });
}

function initAlertListeners() {
    $('#table_alerts').on('click', 'tbody td.r', function () {
        var tr = $(this).closest('tr');
        var row = $("#table_alerts").DataTable().row(tr);
        if (row.child.isShown()) {
            row.child.hide();
            tr.removeClass('shown');
        } else {
            let alertID = row.data()["alert_id"]
            let tableEvidenceID = "table_" + alertID
            row.child(addTableEvidence(tableEvidenceID)).show();
            let evidence = $("#" + tableEvidenceID).DataTable(analysisSubTableDefs["evidence"]);
            let link = "/analysis/evidence/" + active_profile + "/" + active_timewindow + "/" + alertID
            evidence.ajax.url(link).load();
            tr.addClass('shown');
        }
    });
}
/*--------------------------------------------------------------*/

function removeListeners(analysisTag) {
    $("#table_" + analysisTag).off("click", "**")
}

function initAllAnalysisTables() {

    for (const [key, value] of Object.entries(analysisTableDefs)) {
        //remove the default 'Search' text for all DataTable search boxes
        $.extend(true, $.fn.dataTable.defaults, {
            language: {
                search: ""
            }
        });
        // init datatables
        $("#table_" + key).DataTable(value);

        // custom search
        $('[type=search]').each(function () {

            $(this).attr("placeholder", "Search...");
            $(this).before('<span class="fa fa-search"></span>');
        });
    }

}

function initAnalysisPage() {
    initAllAnalysisTables();  // Initialize all analysis tables
    initProfileTwListeners(); // Initialize all profile and tw tables' listeners
    initAnalysisTagListeners(); //Initialize analysisTags listeners
    initHideProfileTWButtonListener();
}

$(document).ready(function () {
    initAnalysisPage();
    document.onkeydown = hotkeyPress;
});

