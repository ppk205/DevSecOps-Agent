<?php
libxml_disable_entity_loader(false);
$doc = new DOMDocument();
$doc->loadXML($data);
