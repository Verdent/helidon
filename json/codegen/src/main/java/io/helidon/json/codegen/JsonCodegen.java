package io.helidon.json.codegen;

import java.util.List;

import io.helidon.codegen.RoundContext;
import io.helidon.codegen.spi.CodegenExtension;
import io.helidon.common.types.TypeInfo;
import io.helidon.common.types.TypeName;

class JsonCodegen implements CodegenExtension {

    @Override
    public void process(RoundContext roundContext) {
//        List<TypeName> list = roundContext.annotatedTypes(Types.JSON_AS_JSON)
//                .stream()
//                .map(TypeInfo::typeName)
//                .toList();
        roundContext.annotatedTypes(Types.JSON_AS_JSON);
        System.out.println();
    }

}
