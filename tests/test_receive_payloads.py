import base64
import gzip
import io
import zipfile

from latvian_einvoice.api.receive import (
    _decrypt_attachments,
    _parse_get_message_raw_response,
)


def _sample_edoc() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("mimetype", "application/vnd.etsi.asic-e+zip")
        archive.writestr("document.txt", "payload")
    return buffer.getvalue()


def test_plain_compressed_attachment_is_unwrapped_without_decryption():
    edoc_zip = _sample_edoc()
    data = {
        "Envelope": {
            "SenderDocument": {
                "DocumentMetadata": {
                    "PayloadReference": {
                        "File": {
                            "Name": "sample.edoc",
                            "Compressed": True,
                            "Content": {"ContentReference": "0"},
                        }
                    }
                }
            }
        },
        "AttachmentsOutput": {
            "AttachmentOutput": {
                "ContentId": "0",
                "FileName": "sample.edoc",
                "Contents": gzip.compress(edoc_zip),
            }
        },
    }

    _decrypt_attachments(data, private_key_path=None, certificate_path=None)

    attachment = data["AttachmentsOutput"]["AttachmentOutput"]
    assert attachment.get("DecryptedContent") is None
    assert attachment["Contents"] == edoc_zip


def test_gzip_magic_is_unwrapped_without_compressed_metadata():
    edoc_zip = _sample_edoc()
    data = {
        "AttachmentsOutput": {
            "AttachmentOutput": {
                "ContentId": "0",
                "Contents": gzip.compress(edoc_zip),
            }
        }
    }

    _decrypt_attachments(data, private_key_path=None, certificate_path=None)

    assert data["AttachmentsOutput"]["AttachmentOutput"]["Contents"] == edoc_zip


def test_explicit_gzip_file_is_preserved_without_compressed_metadata():
    compressed = gzip.compress(b"plain gzipped payload")
    data = {
        "AttachmentsOutput": {
            "AttachmentOutput": {
                "ContentId": "0",
                "FileName": "archive.gz",
                "ContentType": "application/gzip",
                "Contents": compressed,
            }
        }
    }

    _decrypt_attachments(data, private_key_path=None, certificate_path=None)

    assert data["AttachmentsOutput"]["AttachmentOutput"]["Contents"] == compressed


def test_raw_mtom_response_uses_xop_attachment_and_generic_addresses():
    attachment_bytes = b"0123456789ABCDEF"
    multipart = (
        b"--boundary123\r\n"
        b"Content-Type: application/xop+xml; charset=UTF-8; type=\"application/soap+xml\"\r\n"
        b"Content-ID: <rootpart>\r\n\r\n"
        b"<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" "
        b"xmlns:xop=\"http://www.w3.org/2004/08/xop/include\" "
        b"xmlns:u=\"http://vraa.gov.lv/xmlschemas/div/uui/2011/11\">"
        b"<s:Body><u:GetMessageOutput>"
        b"<u:ConfirmationName>GENERIC-CONNECTION-ID</u:ConfirmationName>"
        b"<u:Recipients><u:string>_PRIVATE@40000000000</u:string></u:Recipients>"
        b"<u:Envelope><SenderDocument xmlns=\"http://ivis.eps.gov.lv/XMLSchemas/100001/DIV/v1-0\"/></u:Envelope>"
        b"<u:AttachmentsOutput><u:AttachmentOutput>"
        b"<u:ContentId>0</u:ContentId><u:IsSeparateCall>false</u:IsSeparateCall>"
        b"<u:Contents><xop:Include href=\"cid:part-1\"/></u:Contents>"
        b"</u:AttachmentOutput></u:AttachmentsOutput>"
        b"</u:GetMessageOutput></s:Body></s:Envelope>\r\n"
        b"--boundary123\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Transfer-Encoding: binary\r\n"
        b"Content-ID: <part-1>\r\n\r\n"
        + attachment_bytes
        + b"\r\n--boundary123--\r\n"
    )

    parsed = _parse_get_message_raw_response(multipart)

    assert parsed["ConfirmationName"] == "GENERIC-CONNECTION-ID"
    assert parsed["Recipients"] == ["_PRIVATE@40000000000"]
    attachment = parsed["AttachmentsOutput"]["AttachmentOutput"][0]
    assert base64.b64decode(attachment["Contents"]) == attachment_bytes
