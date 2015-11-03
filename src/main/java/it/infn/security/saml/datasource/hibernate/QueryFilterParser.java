package it.infn.security.saml.datasource.hibernate;

import org.parboiled.BaseParser;
import org.parboiled.Parboiled;
import org.parboiled.Rule;
import org.parboiled.annotations.BuildParseTree;
import org.parboiled.parserunners.ReportingParseRunner;
import org.parboiled.support.ParseTreeUtils;
import org.parboiled.support.ParsingResult;

@BuildParseTree
public class QueryFilterParser
    extends BaseParser<Object> {

    private char[] sepChars = new char[] { ' ', '\t' };

    Rule filter() {
        return Sequence(logicalExpression(),
                ZeroOrMore(Sequence(sep(), FirstOf("and", "or"), sep(), logicalExpression())));
    }

    Rule logicalExpression() {
        return FirstOf(attributeExpression(), valuePath(),
                Sequence(Optional(Sequence("not", sep())), '(', filter(), ')'));
    }

    Rule attributeExpression() {
        return FirstOf(Sequence(attributePath(), sep(), "pr"),
                Sequence(attributePath(), sep(), compOperator(), sep(), compValue()));
    }

    Rule valuePath() {
        return Sequence(attributePath(), '[', valueFilter(), ']');
    }

    Rule valueFilter() {
        return Sequence(logValExpression(),
                ZeroOrMore(Sequence(sep(), FirstOf("and", "or"), sep(), logValExpression())));
    }

    Rule logValExpression() {
        return FirstOf(attributeExpression(), Sequence(Optional(Sequence("not", sep())), '(', filter(), ')'));
    }

    Rule compValue() {
        return FirstOf("false", "true", "null", number(), string());
    }

    Rule compOperator() {
        return FirstOf("eq", "ne", "co", "sw", "ew", "gt", "lt", "ge", "le");
    }

    Rule attributePath() {
        /*
         * TODO missing uri
         */
        return Sequence(attributeName(), Optional(subAttribute()));
    }

    Rule attributeName() {
        return Sequence(alpha(), ZeroOrMore(nameChar()));
    }

    Rule number() {
        return OneOrMore(CharRange('0', '9'));
    }

    Rule string() {
        return Sequence('"', OneOrMore(nameChar()), '"');
    }

    Rule nameChar() {
        return FirstOf('-', '_', alpha(), CharRange('0', '9'));
    }

    Rule subAttribute() {
        return Sequence(".", attributeName());
    }

    Rule alpha() {
        return FirstOf(CharRange('a', 'z'), CharRange('A', 'Z'));
    }

    Rule sep() {
        return AnyOf(sepChars);
    }

    public static void main(String args[]) {
        QueryFilterParser parser = Parboiled.createParser(QueryFilterParser.class);
        @SuppressWarnings("rawtypes")
        ParsingResult<?> result = new ReportingParseRunner(parser.filter()).run(args[0]);
        if (result.matched) {
            System.out.println(ParseTreeUtils.printNodeTree(result));
        } else {
            System.out.println("error");
        }
    }
}
