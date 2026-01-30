import dynamic from "next/dynamic";
import Image from "next/image";

const Portal = dynamic(() => import("@/components/portal"), { ssr: false });

export default function PreLoader({ isLoading }) {
    return (
        isLoading && (
            <Portal>
                <div className={`preloader-wrapper`}>
                    <Image
                        src={`/loader.svg`}
                        alt={`loader`}
                        width={150}
                        height={150}
                        priority={true}
                    />
                    <p className={`preloader-text`}>Loading...</p>
                </div>
            </Portal>
        )
    );
}
