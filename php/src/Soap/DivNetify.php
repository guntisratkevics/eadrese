<?php

declare(strict_types=1);

namespace LatvianEinvoice\Soap;

/**
 * Applies the "netify" XSLT used by the official Java/.NET clients before signing.
 *
 * This normalization matters for ConfirmMessage: DIV verifies the signature over a combined
 * envelope assembled server-side (SenderSection + ServerSection + RecipientConfirmation),
 * so namespace scoping/prefix normalization must match the official client behavior.
 */
final class DivNetify
{
    // Ported from the Python SDK (_NETIFY_XSL), originally reverse engineered from the Java client.
    private const NETIFY_XSL = <<<'XSL'
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:xades1="http://uri.etsi.org/01903/v1.1.1#"
                xmlns:xades3="http://uri.etsi.org/01903/v1.3.2#"
                xmlns:uui="http://vraa.gov.lv/xmlschemas/div/uui/2011/11"
                xmlns:cm="http://ivis.eps.gov.lv/XMLSchemas/100001/DIV/v1-0"
                xmlns:exsl="http://exslt.org/common"
                xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                extension-element-prefixes="exsl"
                exclude-result-prefixes="exsl cm xades1 xades3 uui ds">
    <xsl:output method="xml" omit-xml-declaration="yes" indent="no"/>
    <xsl:strip-space elements="*"/>

    <xsl:template match="@* | text() | comment() | processing-instruction()">
        <xsl:copy/>
    </xsl:template>
    <xsl:template match="*">
        <xsl:element name="{name()}" namespace="{namespace-uri()}">
            <xsl:apply-templates select="@* | node()"/>
        </xsl:element>
    </xsl:template>
    <xsl:template match="uui:*">
        <xsl:element name="{local-name()}" namespace="{namespace-uri()}">
            <xsl:apply-templates select="@* | node()"/>
        </xsl:element>
    </xsl:template>
    <xsl:template match="cm:AddressLVA">
        <xsl:variable name="dummy">
            <AddressLVA xmlns:a="http://ivis.eps.gov.lv/XMLSchemas/100001/Address/v1-1">
                <xsl:apply-templates select="@* | node()"/>
            </AddressLVA>
        </xsl:variable>
        <xsl:copy-of select="exsl:node-set($dummy)/*"/>
    </xsl:template>
    <xsl:template match="cm:AddressLVA/*">
        <xsl:element name="a:{local-name()}"
                     namespace="http://ivis.eps.gov.lv/XMLSchemas/100001/Address/v1-1">
            <xsl:apply-templates select="@* | node()"/>
        </xsl:element>
    </xsl:template>
    <xsl:template match="xades1:QualifyingProperties">
        <xsl:element name="{local-name()}"
                     namespace="http://uri.etsi.org/01903/v1.1.1#">
            <xsl:copy-of select="@*"/>
            <xsl:apply-templates/>
        </xsl:element>
    </xsl:template>
    <xsl:template match="xades3:QualifyingProperties">
        <xsl:element name="{local-name()}"
                     namespace="http://uri.etsi.org/01903/v1.3.2#">
            <xsl:copy-of select="@*"/>
            <xsl:apply-templates/>
        </xsl:element>
    </xsl:template>
    <xsl:template match="ds:Reference/ds:DigestValue/text()">
      <xsl:choose>
        <xsl:when test="contains(.,'&#xA;') or string-length(.) &lt; 77"><xsl:value-of select="."/></xsl:when>
        <xsl:otherwise><xsl:value-of select="concat(substring(.,1, 76),'&#xA;',substring(.,77))"/></xsl:otherwise></xsl:choose></xsl:template>
</xsl:stylesheet>
XSL;

    public static function netifyElement(\DOMElement $root): \DOMElement
    {
        if (!class_exists(\XSLTProcessor::class)) {
            throw new \RuntimeException('ext-xsl is required for DIV netify (ConfirmMessage signing)');
        }

        $src = new \DOMDocument('1.0', 'utf-8');
        $src->formatOutput = false;
        $src->preserveWhiteSpace = false;
        $src->appendChild($src->importNode($root, true));

        $xsl = new \DOMDocument('1.0', 'utf-8');
        $xsl->formatOutput = false;
        $xsl->preserveWhiteSpace = false;
        if (!@$xsl->loadXML(self::NETIFY_XSL)) {
            throw new \RuntimeException('Failed to load netify XSLT');
        }

        $proc = new \XSLTProcessor();
        if (!@$proc->importStylesheet($xsl)) {
            throw new \RuntimeException('Failed to import netify XSLT');
        }

        $out = @$proc->transformToDoc($src);
        if (!$out instanceof \DOMDocument || !$out->documentElement instanceof \DOMElement) {
            throw new \RuntimeException('Netify XSLT returned no document');
        }

        // Ensure consistent serialization/canonicalization behavior.
        $out->formatOutput = false;
        $out->preserveWhiteSpace = false;

        return $out->documentElement;
    }
}

