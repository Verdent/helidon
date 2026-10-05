# io.<wbr>helidon.<wbr>security.<wbr>providers.<wbr>oidc.<wbr>next.<wbr>Oidc<wbr>Remote<wbr>Work<wbr>Config

## Description

Admission limits for high-cardinality OIDC remote work

## Configuration options


<table>
<thead>
<tr>
<th>Key</th>
<th>Type</th>
<th>Default</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>max-<wbr>queued</code>
</td>
<td>
<code>Integer</code>
</td>
<td>
<code>128</code>
</td>
<td>Maximum number of callers waiting for an active operation or same-key result</td>
</tr>
<tr>
<td>
<code>admission-<wbr>timeout</code>
</td>
<td>
<code>Duration</code>
</td>
<td>
<code>PT1S</code>
</td>
<td>Time allowed for an admitted new operation to obtain an active-operation permit</td>
</tr>
<tr>
<td>
<code>max-<wbr>concurrent</code>
</td>
<td>
<code>Integer</code>
</td>
<td>
<code>32</code>
</td>
<td>Maximum number of concurrent remote HTTP operations</td>
</tr>
</tbody>
</table>



---

See the [manifest](manifest.md) for all available types.
