package it.infn.security.saml.datasource.hibernate;

import org.parboiled.BaseParser;
import org.parboiled.Rule;
import org.parboiled.annotations.BuildParseTree;

@BuildParseTree
public class QueryFilterParser
    extends BaseParser<Object> {

    private char[] sepChars = new char[] { ' ', '\t' };

    Rule filter() {
        return FirstOf(attributeExpression(), logicalExpression(), valuePath(),
                Sequence(Optional("not"), '(', filter(), ')'));
    }

    Rule attributeExpression() {
        return FirstOf(Sequence(attributePath(), separator(), "pr"),
                Sequence(attributePath(), separator(), compOperator(), separator(), compValue()));
    }

    Rule logicalExpression() {
        return Sequence(filter(), separator(), FirstOf("and", "or"), separator(), filter());
    }

    Rule valuePath() {
        return Sequence(attributePath(), '[', valueFilter(), ']');
    }

    Rule valueFilter() {
        return FirstOf(attributeExpression(), logicalExpression(), Sequence(Optional("not"), '(', valueFilter(), ')'));
    }

    Rule compValue() {
        return FirstOf("false", "null", "true", "number", "string");
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

    Rule nameChar() {
        return FirstOf('-', '_', alpha(), CharRange('0', '9'));
    }

    Rule subAttribute() {
        return Sequence(".", attributeName());
    }

    Rule alpha() {
        return FirstOf(CharRange('a', 'z'), CharRange('A', 'Z'));
    }

    Rule separator() {
        return AnyOf(sepChars);
    }
}
