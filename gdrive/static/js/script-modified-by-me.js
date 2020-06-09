$(document).ready(function () {

    var selected_files_to_attest = 0;
    var selected_checksums_to_attest = [];
    var attest_commitment = '';


    var selected_files_to_verify = 0;
    var selected_checksums_to_verify = [];


    var asset_table = $('#table').DataTable({

        "oLanguage": {
            "sLengthMenu": 'Show per page: <select>' +
                '<option value="10">10 files</option>' +
                '<option value="20">20 files</option>' +
                '<option value="30">30 files</option>' +
                '<option value="40">40 files</option>' +
                '<option value="50">50 files</option>' +
                '<option value="-1">All files</option>' +
                '</select> '
        },
        language: {
            paginate: {
                next: '>',
                previous: '<'
            }
        },

        dom: '<"top"i>rt<"bottom"flp><"clear">',
        scrollY: "490px",

        scrollCollapse: true,
        autoWidth: false,
        searching: false,
        fixedHeader: {
            header: true,
            footer: true
        }
    });

    var verify_table = $('#table-verify').DataTable({

        "oLanguage": {
            "sLengthMenu": 'Show per page: <select>' +
                '<option value="10">10 files</option>' +
                '<option value="20">20 files</option>' +
                '<option value="30">30 files</option>' +
                '<option value="40">40 files</option>' +
                '<option value="50">50 files</option>' +
                '<option value="-1">All files</option>' +
                '</select> '
        },
        language: {
            paginate: {
                next: '>',
                previous: '<'
            }
        },

        dom: '<"top"i>rt<"bottom"flp><"clear">',
        scrollY: "490px",

        scrollCollapse: true,
        autoWidth: false,
        searching: false,
        fixedHeader: {
            header: true,
            footer: true
        }

    });

    $('#table-attestation-page').DataTable({
        paginate: false,
        searching: false,
    });

    $("#dynamic-tabs").tabs();


    $('#table tbody').on('click', 'tr', function () {
        $(this).toggleClass('selected');

        // Get selected file checksum
        var selected_file_checksum = asset_table.row(this).data()[4];
        if ($(this).hasClass('selected')) {
            if (selected_file_checksum !== 'no checksum') {
                selected_checksums_to_attest.push(selected_file_checksum);
            }
        } else {
            if (selected_file_checksum !== 'no checksum') {
                var index = selected_checksums_to_attest.indexOf(selected_file_checksum);
                if (index !== -1) {
                    selected_checksums_to_attest.splice(index, 1);
                }
            }
        }

        // Get selected files count
        selected_files_to_attest = asset_table.rows('.selected').data().length;
        if (selected_files_to_attest !== 0) {
            $("#selected_files_to_attest").text(selected_files_to_attest + " files selected");
        } else {
            $("#selected_files_to_attest").text("No files selected");
        }

        getAssetCommitment(selected_checksums_to_attest);

    });

    $('#table-verify tbody').on('click', 'tr', function () {
        $(this).toggleClass('selected');
        selected_files_to_verify = verify_table.rows('.selected').data().length;
        if (selected_files_to_verify !== 0) {
            $("#selected_files_to_verify").text(selected_files_to_verify + " files selected");
        } else {
            $("#selected_files_to_verify").text("No files selected");
        }
    });

    $(".form .form-group").change(function () {
        if ($(this).find('input').val()) {
            $(this).find('label').addClass('hasValue');
        } else {
            $(this).find('label').removeClass('hasValue');
        }
    });

    $('#attest_to_mainstay').on('click', function () {

        var slot_id = $('#slotNumber').val();
        var api_key = $('#apikey').val();

        var data = {commitment: attest_commitment, api_token: api_key, slot: slot_id};

        $.ajax({
            url: "/attest",
            type: "POST",
            data: JSON.stringify(data),
            contentType: "application/json; charset=utf-8",
            success: function (data) {
                alert(data);
            }
        });

    });


    function getAssetCommitment(selected_checksums) {

        $.ajax({
            url: "/get_commitment",
            type: "POST",
            data: JSON.stringify({checksums: selected_checksums}),
            contentType: "application/json; charset=utf-8",
            success: function (data) {
                attest_commitment = data;
            }
        });
    }

});


