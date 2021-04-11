import std.conv;
import std.exception;
import std.file;
import std.getopt;
import std.stdio;
import std.path;

import dxml.dom;
import dxml.parser;

int main(string[] args)
{
    bool verbose = false;
    auto helpInfo = getopt(args, "verbose|v", "Tell me more what is happening.", &verbose);
    string usageMsg = "Usage: dmarc-report-analyzer [options] path";
    if (helpInfo.helpWanted)
    {
        defaultGetoptPrinter(usageMsg ~ "\nOptions:", helpInfo.options);
        return  - 1;
    }
    else if (args.length == 1)
    {
        writeln("dmarc-report-analyzer: \033[1;31mfatal error:\033[0m no input path");
        writeln("specify a path where dmarc reports to analyze can be found");
        writeln(usageMsg);
        return  - 1;
    }
    else
    {
        int nbErrors = 0;
        foreach (arg; args[1 .. $])
        {
            nbErrors += processDir(arg, verbose);
        }
        return nbErrors;
    }
}

int processDir(string dirName, bool verbose)
{
    int nbErrors = 0;
    foreach (entryName; dirEntries(dirName, SpanMode.depth))
    {
        if (entryName.isFile)
        {
            if (extension(entryName) == ".xml")
            {
                write("Processing " ~ entryName ~ "... ");
                try
                {
                    processReport(entryName);
                    writeln("\033[32mOK\033[0m.");
                }
                catch (DMARCError e)
                {
                    writeln("\033[31mNOK\033[0m! Found DMARC errors. Report needs deeper analysis.");
                    ++nbErrors;
                }
                catch (InvalidFormat e)
                {
                    writeln("\033[31mNOK\033[0m! Invalid DMARC format. Check the report file and see if the analyzer needs (code) update");
                    ++nbErrors;
                }
                catch (XMLParsingException e)
                {
                    writeln("\033[31mNOK\033[0m! Failed to parse the file (not DMARC report?).");
                    ++nbErrors;
                }
                catch (Exception e)
                {
                    writeln("\033[31mNOK\033[0m! Exception raised: " ~ e.msg);
                    ++nbErrors;
                }
            }
            else if (verbose)
            {
                writeln("Ignoring " ~ entryName ~ " because it is not an xml file.");
            }
        }
    }
    return nbErrors;
}

void processReport(string fileName)
{
    string reportContent = readText(fileName);
    auto dom = parseDOM!simpleXML(reportContent);
    auto root = dom.children[0];
    processFeedback(root);
}

void processFeedback(R)(DOMEntity!(R) entity)
in (entity.name == "feedback")
{
    foreach (child; entity.children)
    {
        if (child.name == "record")
        {
            processRecord(child);
        }
    }
}

void processRecord(R)(DOMEntity!(R) entity)
in (entity.name == "record")
{
    foreach (child; entity.children)
    {
        if (child.name == "row")
        {
            processRow(child);
        }
        else if (child.name == "auth_results")
        {
            processAuthResults(child);
        }
    }
}

void processRow(R)(DOMEntity!(R) entity)
in (entity.name == "row")
{
    bool policyEvaluatedChildFound = false;
    foreach (child; entity.children)
    {
        if (child.name == "policy_evaluated")
        {
            enforce!InvalidFormat(!policyEvaluatedChildFound,
                    "Row DOMEntity has multiple policy_evaluated children");

            processPolicyEvaluated(child);
            policyEvaluatedChildFound = true;
        }
    }
    enforce!InvalidFormat(policyEvaluatedChildFound, "Row DOMEntity has no policy_evaluated child");
}

version (unittest)
{
    string row_OK = "
        <row>
            <source_ip/>
            <count/>
            <policy_evaluated>
                <disposition>none</disposition>
                <dkim>pass</dkim>
                <spf>pass</spf>
            </policy_evaluated>
        </row>";

    string row_NOK_NoPolicyEvaluated = "
        <row>
            <source_ip/>
            <count/>
        </row>";

    string row_NOK_MultiplePolicyEvaluated = "
        <row>
            <source_ip/>
            <count/>
            <policy_evaluated>
                <disposition>none</disposition>
                <dkim>pass</dkim>
                <spf>pass</spf>
            </policy_evaluated>
            <policy_evaluated>
                <disposition>none</disposition>
                <dkim>pass</dkim>
                <spf>pass</spf>
            </policy_evaluated>
        </row>";
}

unittest
{
    auto dom = parseDOM!simpleXML(row_OK);
    auto root = dom.children[0];
    assertNotThrown(processRow(root));
}

unittest
{
    auto dom = parseDOM!simpleXML(row_NOK_NoPolicyEvaluated);
    auto root = dom.children[0];
    assertThrown!InvalidFormat(processRow(root));
}

unittest
{
    auto dom = parseDOM!simpleXML(row_NOK_MultiplePolicyEvaluated);
    auto root = dom.children[0];
    assertThrown!InvalidFormat(processRow(root));
}

void processPolicyEvaluated(R)(DOMEntity!(R) entity)
in (entity.name == "policy_evaluated")
{
    enforce!InvalidFormat(entity.children.length == 3, "DOMEntity "
            ~ entity.name ~ " has an invalid format (children). Expected: 3, found: "
            ~ to!string(entity.children.length));

    foreach (child; entity.children)
    {
        if (child.name == "disposition")
        {
            validateEntityValue!("disposition", "none")(child);
        }
        else if (child.name == "dkim")
        {
            validateEntityValue!("dkim", "pass")(child);
        }
        else if (child.name == "spf")
        {
            validateEntityValue!("spf", "pass")(child);
        }
        else
        {
            throw new InvalidFormat("Unexpected child entry (" ~ child.name
                    ~ ") in " ~ entity.name ~ " DOMEntity");
        }
    }
}

version (unittest)
{
    string policyEvaluated_OK = "
        <policy_evaluated>
            <disposition>none</disposition>
            <dkim>pass</dkim>
            <spf>pass</spf>
        </policy_evaluated>";

    string policyEvaluated_NOK_Disposition = "
        <policy_evaluated>
            <disposition>quarantine</disposition>
            <dkim>pass</dkim>
            <spf>pass</spf>
        </policy_evaluated>";

    string policyEvaluated_NOK_Dkip = "
        <policy_evaluated>
            <disposition>none</disposition>
            <dkim>fail</dkim>
            <spf>pass</spf>
        </policy_evaluated>";

    string policyEvaluated_NOK_Spf = "
        <policy_evaluated>
            <disposition>none</disposition>
            <dkim>pass</dkim>
            <spf>fail</spf>
        </policy_evaluated>";

    string policyEvaluated_NOK_TooManyChildren = "
        <policy_evaluated>
            <disposition>none</disposition>
            <dkim>pass</dkim>
            <spf>fail</spf>
            <wrong>fail</wrong>
        </policy_evaluated>";

    string policyEvaluated_NOK_UnexpectedChildEntry = "
        <policy_evaluated>
            <disposition>none</disposition>
            <dkim>pass</dkim>
            <wrong>fail</wrong>
        </policy_evaluated>";
}

unittest
{
    auto dom = parseDOM!simpleXML(policyEvaluated_OK);
    auto root = dom.children[0];
    assertNotThrown(processPolicyEvaluated(root));
}

unittest
{
    auto dom = parseDOM!simpleXML(policyEvaluated_NOK_Disposition);
    auto root = dom.children[0];
    assertThrown!DMARCError(processPolicyEvaluated(root));
}

unittest
{
    auto dom = parseDOM!simpleXML(policyEvaluated_NOK_Dkip);
    auto root = dom.children[0];
    assertThrown!DMARCError(processPolicyEvaluated(root));
}

unittest
{
    auto dom = parseDOM!simpleXML(policyEvaluated_NOK_Spf);
    auto root = dom.children[0];
    assertThrown!DMARCError(processPolicyEvaluated(root));
}

unittest
{
    auto dom = parseDOM!simpleXML(policyEvaluated_NOK_TooManyChildren);
    auto root = dom.children[0];
    assertThrown!InvalidFormat(processPolicyEvaluated(root));
}

unittest
{
    auto dom = parseDOM!simpleXML(policyEvaluated_NOK_UnexpectedChildEntry);
    auto root = dom.children[0];
    assertThrown!InvalidFormat(processPolicyEvaluated(root));
}

void validateEntityValue(string entityName, string entityValue, R)(DOMEntity!(R) entity)
in (entity.name == entityName)
{
    enforce!InvalidFormat(entity.children.length == 1, "DOMEntity "
            ~ entity.name ~ " has an invalid format (children). Expected: 1, found: "
            ~ to!string(entity.children.length));

    auto value = entity.children[0];
    enforce!InvalidFormat(value.type == EntityType.text,
            "Child DOMEntity of DOMEntity:" ~ entity.name ~ " is not text");
    if (value.text != entityValue)
    {
        throw new DMARCError("DMARC error: " ~ entity.name ~ " => " ~ value.text);
    }
}

version (unittest)
{
    string disposition_OK = "<disposition>none</disposition>";
    string disposition_NOK_DMARCError = "<disposition>reject</disposition>";
    string disposition_NOK_NoValue = "<disposition/>";
    string disposition_NOK_ValueNotText = "<disposition><none/></disposition>";
}

unittest
{
    auto dom = parseDOM!simpleXML(disposition_OK);
    auto root = dom.children[0];
    assertNotThrown(validateEntityValue!("disposition", "none")(root));
}

unittest
{
    auto dom = parseDOM!simpleXML(disposition_NOK_DMARCError);
    auto root = dom.children[0];
    assertThrown!DMARCError(validateEntityValue!("disposition", "none")(root));
}

unittest
{
    auto dom = parseDOM!simpleXML(disposition_NOK_NoValue);
    auto root = dom.children[0];
    assertThrown!InvalidFormat(validateEntityValue!("disposition", "none")(root));
}

unittest
{
    auto dom = parseDOM!simpleXML(disposition_NOK_ValueNotText);
    auto root = dom.children[0];
    assertThrown!InvalidFormat(validateEntityValue!("disposition", "none")(root));
}

void processAuthResults(R)(DOMEntity!(R) entity)
in (entity.name == "auth_results")
{
    bool spfEntryFound = false;
    foreach (child; entity.children)
    {
        if (child.name == "spf")
        {
            validateAuthResult!("spf")(child);
            spfEntryFound = true;
        }
        else if (child.name == "dkim")
        {
            validateAuthResult!("dkim")(child);
        }
    }
    enforce!InvalidFormat(spfEntryFound, "DOMEntity " ~ entity.name ~ " has no SPF entries");
}

version (unittest)
{
    string authResults_OK = "
        <auth_results>
            <spf>
                <domain>my.domain</domain>
                <result>pass</result>
            </spf>
            <dkim>
                <domain>my.domain</domain>
                <result>pass</result>
            </dkim>
        </auth_results>";

    string authResults_NOK_NoSpf = "
        <auth_results>
            <dkim>
                <domain>my.domain</domain>
                <result>pass</result>
            </dkim>
        </auth_results>";

    string authResults_OK_MultipleSpfAndDkim = "
        <auth_results>
            <spf>
                <domain>my.domain</domain>
                <result>pass</result>
            </spf>
            <spf>
                <domain>my.domain</domain>
                <result>pass</result>
            </spf>
            <dkim>
                <domain>my.domain</domain>
                <result>pass</result>
            </dkim>
            <dkim>
                <domain>my.domain</domain>
                <result>pass</result>
            </dkim>
        </auth_results>";
}

unittest
{
    auto dom = parseDOM!simpleXML(authResults_OK);
    auto root = dom.children[0];
    assertNotThrown(processAuthResults(root));
}

unittest
{
    auto dom = parseDOM!simpleXML(authResults_NOK_NoSpf);
    auto root = dom.children[0];
    assertThrown!InvalidFormat(processAuthResults(root));
}

unittest
{
    auto dom = parseDOM!simpleXML(authResults_OK_MultipleSpfAndDkim);
    auto root = dom.children[0];
    assertNotThrown(processAuthResults(root));
}

void validateAuthResult(string authResultType, R)(DOMEntity!(R) entity)
in (entity.name == authResultType)
{
    bool resultEntityFound = false;
    foreach (child; entity.children)
    {
        if (child.name == "result")
        {
            enforce!InvalidFormat(!resultEntityFound,
                    "DOMEntity " ~ entity.name ~ " has multiple result value entries");

            validateEntityValue!("result", "pass")(child);
            resultEntityFound = true;
        }
    }
    enforce!InvalidFormat(resultEntityFound,
            "DOMEntity " ~ entity.name ~ " has no result value entries");
}

version (unittest)
{
    string authResultSpf_OK = "
        <spf>
            <domain>my.domain</domain>
            <result>pass</result>
        </spf>";

    string authResultSpf_NOK_ResultFail = "
        <spf>
            <domain>my.domain</domain>
            <result>fail</result>
        </spf>";

    string authResultSpf_NOK_NoResult = "
        <spf>
            <domain>my.domain</domain>
        </spf>";

    string authResultSpf_NOK_MultipleResults = "
        <spf>
            <domain>my.domain</domain>
            <result>pass</result>
            <result>fail</result>
        </spf>";
}

unittest
{
    auto dom = parseDOM!simpleXML(authResultSpf_OK);
    auto root = dom.children[0];
    assertNotThrown(validateAuthResult!("spf")(root));
}

unittest
{
    auto dom = parseDOM!simpleXML(authResultSpf_NOK_ResultFail);
    auto root = dom.children[0];
    assertThrown!DMARCError(validateAuthResult!("spf")(root));
}

unittest
{
    auto dom = parseDOM!simpleXML(authResultSpf_NOK_NoResult);
    auto root = dom.children[0];
    assertThrown!InvalidFormat(validateAuthResult!("spf")(root));
}

unittest
{
    auto dom = parseDOM!simpleXML(authResultSpf_NOK_MultipleResults);
    auto root = dom.children[0];
    assertThrown!InvalidFormat(validateAuthResult!("spf")(root));
}

class InvalidFormat : Exception
{
    mixin basicExceptionCtors;
}

class DMARCError : Exception
{
    mixin basicExceptionCtors;
}

