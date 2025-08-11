from lxml import etree

def validate_xml(xml_path, xsd_path):
    # Parse XSD schema
    with open(xsd_path, 'rb') as xsd_file:
        schema_root = etree.XML(xsd_file.read())
        schema = etree.XMLSchema(schema_root)

    # Parse XML file
    with open(xml_path, 'rb') as xml_file:
        xml_doc = etree.parse(xml_file)

    # Validate
    is_valid = schema.validate(xml_doc)
    if is_valid:
        print("XML is valid.")
    else:
        print("XML is invalid.")
        for error in schema.error_log:
            print(f"Line {error.line}: {error.message}")
    return is_valid

# Example usage:
validate_xml("./validators/training/sample3-bgp.xml", "./validators/xsd/sample_based.xsd")
