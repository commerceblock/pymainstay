$(document).ready(function () {

    var selected_files_to_attest = 0;
    var selected_checksums_to_attest = [];
    var attest_commitment = '';

    var selected_files_to_verify = 0;
    var selected_checksums_to_verify = [];
    var verify_commitment = '';

    // Data table on Attest tab
    var asset_table = $('#table-attest').DataTable({
        select: {
            style: 'single'
        },

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

    // Data table on Verify tab
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

    // Data table containing all selected files to verify or attest
    var table_attestationPage = $('#table-attestation-page').DataTable({
        paging: false,
        searching: false,
        ordering: false,
        bPaginate: false,
        info: false
    });

    // Initialize tab
    $("#dynamic-tabs").tabs();

    // Actions on Attest tab
    $('#table-attest tbody').on('click', 'tr', function () {
        $(this).toggleClass('selected');

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
            getCommitment(selected_checksums_to_attest, 'attest');
        } else {
            $("#selected_files_to_attest").text("No files selected");
            attest_commitment = '';
            $('#attest-commitment').val('');
        }
    });

    // Actions on Verify tab
    $('#table-verify tbody').on('click', 'tr', function () {
        $(this).toggleClass('selected');

        var selected_file_checksum = verify_table.row(this).data()[4];
        if ($(this).hasClass('selected')) {
            if (selected_file_checksum !== 'no checksum') {
                selected_checksums_to_verify.push(selected_file_checksum);
            }
        } else {
            if (selected_file_checksum !== 'no checksum') {
                var index = selected_checksums_to_verify.indexOf(selected_file_checksum);
                if (index !== -1) {
                    selected_checksums_to_verify.splice(index, 1);
                }
            }
        }

        // Get selected files count
        selected_files_to_verify = verify_table.rows('.selected').data().length;
        if (selected_files_to_verify !== 0) {
            $("#selected_files_to_verify").text(selected_files_to_verify + " files selected");
            getCommitment(selected_checksums_to_verify, 'verify');
        } else {
            $("#selected_files_to_verity").text("No files selected");
            verify_commitment = '';
            $('#verify-commitment').val('');
        }
    });

    // Inputs for slot number, commitment and api key
    $(".form .form-group").change(function () {

        if ($(this).find('input').val()) {

            $(this).find('label').addClass('hasValue');

        } else {

            $(this).find('label').removeClass('hasValue');
        }
    });

    $('#attestResultModal').on('hidden.bs.modal', function () {
        $('#attest-result-form').find("input[type=text]").attr('value', '');
    });

    $("#attest_form").submit(function (e) {
        e.preventDefault();

        var data = getFormData($(this));

        $.ajax({
            url: "/attest",
            type: "POST",
            data: JSON.stringify(data),
            contentType: "application/json; charset=utf-8",
            success: function (data) {
                $('#attestResultModal').modal('show');

                $('#attest-result-form input[name="response"]').attr("value", data.response);
                $('#attest-result-form input[name="date"]').attr("value", data.date);
                $('#attest-result-form input[name="allowance"]').attr("value", data.allowance);

            }
        });
    });

    $('#verifyResultModal').on('hidden.bs.modal', function () {
        $('#verify-result-form').find("input[type=text]").attr('value', '');
    });

    $("#verify_form").submit(function (e) {
        e.preventDefault();

        var data = getFormData($(this));

        $.ajax({
            url: "/verify",
            type: "POST",
            data: JSON.stringify(data),
            contentType: "application/json; charset=utf-8",
            success: function (data) {
                $('#verifyResultModal').modal('show');

                $('#verify-result-form input[name="commitment"]').attr("value", data.commitment);
                $('#verify-result-form input[name="slot"]').attr("value", data.slot);
                $('#verify-result-form input[name="txid"]').attr("value", data.txid);
                $('#verify-result-form input[name="bitcoin_block"]').attr("value", data.bitcoin_block);
                $('#verify-result-form input[name="height"]').attr("value", data.height);
                $('#verify-result-form input[name="date"]').attr("value", data.date);
            }
        });
    });

    function getCommitment(selected_checksums, sender) {
        $.ajax({
            url: "/get_commitment",
            type: "POST",
            data: JSON.stringify({checksums: selected_checksums}),
            contentType: "application/json; charset=utf-8",
            success: function (data) {

                if (sender === 'attest') {
                    attest_commitment = data;
                    $('#attest-commitment').val(attest_commitment);
                } else if (sender === 'verify') {
                    verify_commitment = data;
                    $('#verify-commitment').val(verify_commitment);
                }
            }
        });
    }

});


function getFormData($form) {
    var unindexed_array = $form.serializeArray();
    var indexed_array = {};

    $.map(unindexed_array, function (n, i) {
        indexed_array[n['name']] = n['value'];
    });

    return indexed_array;
}

function parse(str) {
    var args = [].slice.call(arguments, 1),
        i = 0;

    return str.replace(/%s/g, () => args[i++]);
}