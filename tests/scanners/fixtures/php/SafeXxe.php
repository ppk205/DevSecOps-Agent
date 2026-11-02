<?php
libxml_disable_entity_loader(true);
$doc = new DOMDocument();
$doc->loadXML($data, LIBXML_NONET);
